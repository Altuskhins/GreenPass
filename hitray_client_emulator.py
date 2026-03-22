#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Any


CFLINK_V1_ALT_PREFIX = "https://hitray.io/"
CFLINK_V1_PREFIX = "https://hvpn.io/"
CFLINK_V1_PREFIX_COMP = "hitvpn://"
CFLINK_V1_TAG = 1
CFLINK_V1_HASH_KEY = b"IIkYdtWtkU"
CFLINK_VLESS_PREFIX = "vless://"
APP_LINK_PROTO_WG = 0
APP_LINK_PROTO_OBF = 1
APP_LINK_PROTO_VLESS = 2
VLESS_FP_NAMES = [
    "random",
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "randomized",
]


@dataclass
class WrappedConfig:
    proto: int
    cfg_data: bytes


@dataclass
class WrappedLink:
    vid: int = 0
    min_app_ver: int = 0
    conf_class: int | None = None
    configs: list[WrappedConfig] | None = None


@dataclass
class VlessData:
    vid: int = 0
    uuid: bytes = b""
    server_pub_key: bytes = b""
    server_ip4: int = 0
    server_port: int = 0
    type: int = 0
    security: int = 0
    sni: str = ""
    fp: int = 0
    sid: str = ""
    spx: str = "%2F"
    flow: str = "xtls-rprx-vision"


class CborReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self) -> Any:
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if major == 0:
            return self._read_uint(additional)
        if major == 1:
            return -1 - self._read_uint(additional)
        if major == 2:
            length = self._read_uint(additional)
            return self._take(length)
        if major == 3:
            length = self._read_uint(additional)
            return self._take(length).decode("utf-8")
        if major == 4:
            length = self._read_uint(additional)
            return [self.read() for _ in range(length)]
        if major == 5:
            length = self._read_uint(additional)
            out: dict[Any, Any] = {}
            for _ in range(length):
                key = self.read()
                value = self.read()
                out[key] = value
            return out
        if major == 6:
            self._read_uint(additional)
            return self.read()
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise ValueError(f"unsupported CBOR simple value: {additional}")
        raise ValueError(f"unsupported CBOR major type: {major}")

    def _read_uint(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            return self._take(1)[0]
        if additional == 25:
            return int.from_bytes(self._take(2), "big")
        if additional == 26:
            return int.from_bytes(self._take(4), "big")
        if additional == 27:
            return int.from_bytes(self._take(8), "big")
        raise ValueError(f"unsupported CBOR uint additional info: {additional}")

    def _take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("unexpected end of CBOR data")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk


def clear_link(text: str) -> str:
    text = text.strip()
    if text.startswith("https://") or text.startswith(CFLINK_VLESS_PREFIX) or text.startswith("hitvpn://"):
        return text
    match = re.search(r"https://\S+|vless://\S+|hitvpn://\S+", text)
    if not match:
        return text
    return match.group(0)


def decode_base64_urlsafe_no_padding(data: str) -> bytes:
    normalized = data.replace("-", "+").replace("_", "/")
    padding = (-len(normalized)) % 4
    if padding:
        normalized += "=" * padding
    return base64.b64decode(normalized)


def little_endian_conversion(data: bytes) -> int:
    return int.from_bytes(data, "little")


def obfuscate_link2_wrap_data(salt: bytes, payload: bytearray) -> None:
    base = hashlib.sha256()
    base.update(CFLINK_V1_HASH_KEY)
    base.update(salt)
    current = base.copy().digest()
    index = 0
    for i in range(len(payload)):
        if index >= len(current):
            base.update(current[:8])
            current = base.copy().digest()
            index = 0
        payload[i] ^= current[index]
        index += 1


def decode_wrap_payload(encoded: str) -> WrappedLink:
    decoded = decode_base64_urlsafe_no_padding(encoded)
    if len(decoded) < 32:
        raise ValueError("too short link data")
    if decoded[0] != CFLINK_V1_TAG:
        raise ValueError("invalid applink2 tag")

    salt = decoded[1:5]
    hash_prefix = decoded[5:9]
    payload = bytearray(decoded[9:])

    if little_endian_conversion(salt) != 0:
        obfuscate_link2_wrap_data(salt, payload)

    digest = hashlib.sha256(payload).digest()
    if digest[:4] != hash_prefix:
        raise ValueError("check hash mismatch")

    root = CborReader(bytes(payload)).read()
    if not isinstance(root, dict):
        raise ValueError("wrapped payload is not a CBOR map")

    wrapped = WrappedLink(configs=[])
    wrapped.vid = int(root.get(1, 0))
    wrapped.min_app_ver = int(root.get(2, 0))
    conf_class = root.get(3)
    wrapped.conf_class = int(conf_class) if conf_class is not None else None

    for cfg_item in root.get(4, []):
        if not isinstance(cfg_item, dict):
            continue
        proto = int(cfg_item.get(1, 0))
        cfg_data = cfg_item.get(2, b"")
        if not isinstance(cfg_data, (bytes, bytearray)):
            raise ValueError("invalid cfg_data type in wrapped config")
        wrapped.configs.append(WrappedConfig(proto=proto, cfg_data=bytes(cfg_data)))

    return wrapped


def decode_vless_cfg(cfg_data: bytes, vid: int) -> VlessData:
    root = CborReader(cfg_data).read()
    if not isinstance(root, dict):
        raise ValueError("vless cfg is not a CBOR map")

    data = VlessData(vid=vid)
    if 1 in root:
        data.uuid = bytes(root[1])
    if 2 in root:
        data.server_pub_key = bytes(root[2])
    if 3 in root:
        data.server_ip4 = int(root[3])
    if 4 in root:
        data.server_port = int(root[4])
    if 5 in root:
        data.type = int(root[5])
    if 6 in root:
        data.security = int(root[6])
    if 7 in root:
        data.sni = str(root[7])
    if 8 in root:
        data.fp = int(root[8])
    if 9 in root:
        data.sid = str(root[9])
    if 10 in root:
        data.spx = str(root[10])
    if 11 in root:
        data.flow = str(root[11])
    return data


def ip4_to_string(value: int) -> str:
    return str(IPv4Address(value))


def uuid_bytes_to_string(value: bytes) -> str:
    hexed = value.hex()
    if len(hexed) != 32:
        return hexed
    return f"{hexed[0:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:32]}"


def to_client_vless_uri(data: VlessData) -> str:
    network = "udp" if data.type == 1 else "tcp"
    security = "reality" if data.security != 0 else "none"
    pbk = base64.urlsafe_b64encode(data.server_pub_key).decode("ascii").rstrip("=")
    return (
        f"{CFLINK_VLESS_PREFIX}"
        f"{uuid_bytes_to_string(data.uuid)}@{ip4_to_string(data.server_ip4)}:{data.server_port}"
        f"?type={network}"
        f"&security={security}"
        f"&pbk={pbk}"
        f"&sni={data.sni}"
        f"&fp=random"
        f"&sid=42"
        f"&spx=%2F"
        f"&flow=xtls-rprx-vision"
    )


def classify_link(link: str) -> str:
    if link.startswith(CFLINK_VLESS_PREFIX):
        return "direct_vless"
    if link.startswith(CFLINK_V1_PREFIX):
        return "wrapped_hvpn"
    if link.startswith(CFLINK_V1_ALT_PREFIX):
        return "wrapped_hitray_alt"
    if link.startswith(CFLINK_V1_PREFIX_COMP):
        return "wrapped_hitvpn_scheme"
    return "unknown"


def emulate(link: str) -> dict[str, Any]:
    cleaned = clear_link(link)
    kind = classify_link(cleaned)
    result: dict[str, Any] = {
        "input": link,
        "cleaned": cleaned,
        "kind": kind,
        "accepted_by_check_link_new": kind in {
            "direct_vless",
            "wrapped_hvpn",
            "wrapped_hitray_alt",
            "wrapped_hitvpn_scheme",
        },
    }

    if kind == "direct_vless":
        result["generated_links"] = [cleaned]
        return result

    if kind not in {"wrapped_hvpn", "wrapped_hitray_alt", "wrapped_hitvpn_scheme"}:
        raise ValueError("unsupported link format for local emulator")

    if kind == "wrapped_hvpn":
        encoded = cleaned[len(CFLINK_V1_PREFIX) :]
    elif kind == "wrapped_hitray_alt":
        encoded = cleaned[len(CFLINK_V1_ALT_PREFIX) :]
    else:
        encoded = cleaned[len(CFLINK_V1_PREFIX_COMP) :]

    wrapped = decode_wrap_payload(encoded)
    wrapped_out: dict[str, Any] = {
        "vid": wrapped.vid,
        "min_app_ver": wrapped.min_app_ver,
        "conf_class": wrapped.conf_class,
        "config_count": len(wrapped.configs or []),
        "configs": [],
    }
    generated_links: list[str] = []

    for index, cfg in enumerate(wrapped.configs or [], start=1):
        cfg_out: dict[str, Any] = {
            "index": index,
            "proto": cfg.proto,
            "proto_name": {
                APP_LINK_PROTO_WG: "wireguard",
                APP_LINK_PROTO_OBF: "obf",
                APP_LINK_PROTO_VLESS: "vless",
            }.get(cfg.proto, f"unknown_{cfg.proto}"),
        }
        if cfg.proto == APP_LINK_PROTO_VLESS:
            vless = decode_vless_cfg(cfg.cfg_data, wrapped.vid)
            fp_name = VLESS_FP_NAMES[vless.fp] if 0 <= vless.fp < len(VLESS_FP_NAMES) else f"unknown_{vless.fp}"
            generated = to_client_vless_uri(vless)
            generated_links.append(generated)
            cfg_out["decoded"] = {
                "vid": vless.vid,
                "uuid": uuid_bytes_to_string(vless.uuid),
                "server_ip4": ip4_to_string(vless.server_ip4),
                "server_port": vless.server_port,
                "type": vless.type,
                "security": vless.security,
                "sni": vless.sni,
                "fp": vless.fp,
                "fp_name": fp_name,
                "sid": vless.sid,
                "spx": vless.spx,
                "flow": vless.flow,
                "server_pub_key_base64url": base64.urlsafe_b64encode(vless.server_pub_key).decode("ascii").rstrip("="),
            }
            cfg_out["client_generated_vless_uri"] = generated
        else:
            cfg_out["cfg_data_base64url"] = base64.urlsafe_b64encode(cfg.cfg_data).decode("ascii").rstrip("=")
            cfg_out["cfg_data_len"] = len(cfg.cfg_data)
        wrapped_out["configs"].append(cfg_out)

    result["wrapped"] = wrapped_out
    result["generated_links"] = generated_links
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Local emulator of Hitray client link decoding")
    parser.add_argument("link", help="vless://, https://hvpn.io/..., https://hitray.io/... or hitvpn://...")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    try:
        result = emulate(args.link)
    except Exception as exc:
        print(json.dumps({"error": str(exc), "input": args.link}, ensure_ascii=False, indent=2))
        return 1

    if args.pretty:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
