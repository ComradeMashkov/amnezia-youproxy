#!/usr/bin/env python3
"""Route an existing Amnezia Xray installation through an authenticated SOCKS5 proxy."""

import copy
import getpass
import http.client
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile


CONTAINER = "amnezia-xray"
MOUNT = "/opt/amnezia/xray"
CONFIG = "server.json"


def validate_credentials(user, password):
    for name, value in (("Логин", user), ("Пароль", password)):
        if not 1 <= len(value.encode("utf-8")) <= 255:
            raise ValueError(f"{name} должен занимать от 1 до 255 байт в UTF-8")


def make_config(config, host, port, user, password):
    validate_credentials(user, password)
    outbounds = config.get("outbounds", [])
    if (len(outbounds) != 1 or outbounds[0].get("protocol") != "freedom"
            or set(outbounds[0]) - {"protocol", "tag", "settings"}
            or outbounds[0].get("settings")
            or config.get("dns") or config.get("routing")):
        raise ValueError("Обнаружены существующие особые настройки выхода, DNS или маршрутизации. Скрипт их не изменяет.")
    if not any(i.get("protocol") == "vless" for i in config.get("inbounds", [])):
        raise ValueError("В конфигурации не найден входящий VLESS")
    result = copy.deepcopy(config)
    result["outbounds"] = [
        {"tag": "isp-egress", "protocol": "socks", "settings": {
            "address": host, "port": port, "user": user, "pass": password}},
        {"tag": "isp-dns", "protocol": "dns", "settings": {}},
        {"tag": "blocked-udp", "protocol": "blackhole", "settings": {}},
    ]
    result["dns"] = {"servers": ["https://1.1.1.1/dns-query"],
                     "queryStrategy": "UseIPv4", "tag": "isp-dns-query"}
    result["routing"] = {"domainStrategy": "AsIs", "rules": [
        {"type": "field", "inboundTag": ["isp-dns-query"], "outboundTag": "isp-egress"},
        {"type": "field", "network": "tcp,udp", "port": "53", "outboundTag": "isp-dns"},
        {"type": "field", "network": "udp", "outboundTag": "blocked-udp"},
    ]}
    return result


def read_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("Прокси неожиданно закрыл соединение")
        data += chunk
    return data


def check_proxy(host, port, user, password):
    validate_credentials(user, password)
    username, secret = user.encode(), password.encode()
    with socket.create_connection((host, port), timeout=15) as sock:
        sock.sendall(b"\x05\x01\x02")
        if read_exact(sock, 2) != b"\x05\x02":
            raise ConnectionError("Прокси не предложил авторизацию SOCKS5 по логину и паролю")
        sock.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(secret)]) + secret)
        if read_exact(sock, 2) != b"\x01\x00":
            raise ConnectionError("Прокси отклонил логин или пароль")
        target = b"api.ipify.org"
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + b"\x01\xbb")
        reply = read_exact(sock, 4)
        if reply[:2] != b"\x05\x00":
            raise ConnectionError("Прокси не смог открыть тестовый сайт")
        sizes = {1: 4, 4: 16}
        if reply[3] == 3:
            length = read_exact(sock, 1)[0]
        elif reply[3] in sizes:
            length = sizes[reply[3]]
        else:
            raise ConnectionError("Прокси вернул неизвестный тип адреса")
        read_exact(sock, length + 2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname="api.ipify.org") as secure:
            secure.sendall(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(secure)
            response.begin()
            if response.status != 200:
                raise ConnectionError(f"Тестовый сайт вернул HTTP {response.status}")
            return str(ipaddress.ip_address(response.read(128).decode("ascii").strip()))


def docker(*args, capture=False):
    return subprocess.run(["docker", *args], check=True,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE)


def config_directory():
    data = json.loads(docker("inspect", CONTAINER, capture=True).stdout)[0]
    if not data["State"]["Running"]:
        raise ValueError("Контейнер amnezia-xray не запущен")
    mounts = [m for m in data["Mounts"] if m["Destination"] == MOUNT]
    if len(mounts) != 1:
        raise ValueError("Не найден каталог данных контейнера Xray")
    return Path(mounts[0]["Source"])


def install_config(directory, config, expected_original=None):
    original = directory / CONFIG
    if original.is_symlink() or not original.is_file():
        raise ValueError("Ожидался обычный файл server.json")
    fd, temp_name = tempfile.mkstemp(prefix=".proxy-config-", suffix=".json", dir=directory)
    temp = Path(temp_name)
    backup = None
    installed = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(config, file, indent=2, ensure_ascii=False)
            file.flush()
            os.fsync(file.fileno())
        docker("exec", CONTAINER, "xray", "run", "-test", "-config", f"{MOUNT}/{temp.name}")
        if expected_original is not None and original.read_bytes() != expected_original:
            raise RuntimeError("Настройки изменились во время проверки. Повторите запуск.")
        fd, backup_name = tempfile.mkstemp(prefix="server.json.backup-", dir=directory)
        os.close(fd)
        backup = Path(backup_name)
        shutil.copyfile(original, backup)
        os.chmod(backup, 0o600)
        os.replace(temp, original)
        installed = True
        docker("restart", CONTAINER)
        if not json.loads(docker("inspect", CONTAINER, capture=True).stdout)[0]["State"]["Running"]:
            raise RuntimeError("Контейнер не запустился")
        return backup
    except BaseException:
        if installed and backup:
            shutil.copyfile(backup, original)
            os.chmod(original, 0o600)
            try:
                docker("restart", CONTAINER)
            except (OSError, subprocess.CalledProcessError):
                print("Не удалось запустить контейнер после отката. Проверьте Docker и резервную копию.", file=sys.stderr)
        raise
    finally:
        temp.unlink(missing_ok=True)


def main():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ValueError("Запустите скрипт от root: sudo python3 configure_proxy.py")
    directory = config_directory()
    original_bytes = (directory / CONFIG).read_bytes()
    original = json.loads(original_bytes)
    host = input("SOCKS5 адрес прокси: ").strip()
    if not host or any(c.isspace() for c in host):
        raise ValueError("Укажите адрес прокси без пробелов")
    port = int(input("SOCKS5 порт прокси: ").strip())
    if not 1 <= port <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535")
    user = input("Логин прокси: ").strip()
    password = getpass.getpass("Пароль прокси (не отображается): ")
    updated = make_config(original, host, port, user, password)
    print("Проверяю SOCKS5 и выход в интернет через прокси...")
    print("Внешний IP прокси:", check_proxy(host, port, user, password))
    backup = install_config(directory, updated, original_bytes)
    print("Xray перезапущен. Резервная копия:", backup)
    print("Проверьте VPN на устройстве и откройте https://api.ipify.org")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, ConnectionError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        sys.exit(1)
