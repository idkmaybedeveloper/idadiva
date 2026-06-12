import shutil
import sys
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ida_patcher")

# JS keygen search/replace for unk_1C419A0 (license RSA pub key)
SEARCH_HEX = (
    "29f4481f796f9f66f2ff13cc4ab5b54f60845db603ba2c0bac8a9bc4b6cbdefc"
    "5c62bfc2f5ee850ac45ea97ad347e8b56dba5085af8c8aad9cc2ec626ca78a06"
    "8006d658f68651da31a0a77c65a70ed73a40d53b08edd403c095aa0bcffa52f3"
    "13ebcacaaa2ce5024a4e2b9aa70fc6092f38ae094d71e43f7690b5ddd3e9e4f7"
)
REPLACE_HEX = (
    "a107b71c8a08ba5350934f7cf6e81be3a24dc2e35f7200d80cbd70b37ed6811d"
    "d2146d3cb7e20ad19b2544c0ef14c5c66ffbbdf226ec3f3d544c04385303ca4a"
    "7179299340022f5d50948bcf8a60307e2c196329e51a5296dc419e40fef3ef7c"
    "6f015a09ebd979e79615338985643e666c14897f9f597e11f44341f496d56861"
)


def patch_library(file_path: Path) -> bool:
    if not file_path.exists():
        logger.error(f"file not found: {file_path}")
        return False

    with open(file_path, "rb") as f:
        data = bytearray(f.read())

    search = bytes.fromhex(SEARCH_HEX)
    replace = bytes.fromhex(REPLACE_HEX)

    if data.find(replace) != -1:
        logger.info(f"{file_path.name}: already patched")
        return True

    count, pos = 0, 0
    while True:
        idx = data.find(search, pos)
        if idx == -1:
            break
        data[idx:idx + 128] = replace
        pos = idx + 128
        count += 1

    if count == 0:
        logger.error(f"{file_path.name}: original key not found (wrong version or already patched differently?)")
        return False

    backup = file_path.with_suffix(file_path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(file_path, backup)
        logger.info(f"backup: {backup.name}")

    with open(file_path, "wb") as f:
        f.write(data)

    logger.info(f"patched {file_path.name}: replaced {count} occurrence(s)")
    return True


def lib_names() -> list[str]:
    if sys.platform == "darwin":
        return ["libida.dylib", "libida32.dylib"]
    elif sys.platform == "win32":
        return ["ida.dll", "ida32.dll"]
    return ["libida.so", "libida32.so"]


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("-d", "--ida-dir"):
        print(f"usage: {sys.argv[0]} -d <ida-dir>")
        sys.exit(1)

    ida_dir = Path(sys.argv[2])
    targets = [ida_dir / name for name in lib_names()]

    ok = sum(patch_library(t) for t in targets)
    if ok == len(targets):
        logger.info("all targets patched! (─‿‿─)")
    else:
        logger.warning(f"patched {ok}/{len(targets)}")


if __name__ == "__main__":
    main()
