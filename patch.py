import argparse
import shutil
import sys
from pathlib import Path
import logging

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ida_patcher")

# original keys from ida pro 9.3
ORIG_N_HEX = "edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93" # :scared:
ORIG_E_HEX = "13000000"

# exponent is always 0xA0 bytes after modulus n in libida
EXPONENT_OFFSET_FROM_N = 0xA0

def patch_library(file_path: Path, new_n_bytes: bytes, new_e_bytes: bytes) -> bool:
    """
    patches a single library file, replacing the rsa pub key
    returns True if patched, False if already patched or failed.
    """
    if not file_path.exists():
        logger.error(f"file not found: {file_path}")
        return False
        
    with open(file_path, "rb") as f:
        data = bytearray(f.read())
        
    orig_n_bytes = bytes.fromhex(ORIG_N_HEX)
    orig_e_bytes = bytes.fromhex(ORIG_E_HEX)
    
    # check if it has the original key
    n_idx = data.find(orig_n_bytes)
    
    if n_idx == -1:
        # check if already patched with our key
        if data.find(new_n_bytes) != -1:
            logger.info(f"{file_path.name} is already patched with the provided key!!!")
            return True
            
        logger.error(f"couldt find the original rsa key in {file_path.name}. wrong version or already patched with a different key?..")
        return False
        
    # verify the original e is where we expect it
    e_idx = n_idx + EXPONENT_OFFSET_FROM_N
    if data[e_idx:e_idx+4] != orig_e_bytes:
        logger.warning(f"found n at offset {hex(n_idx)}, but e at {hex(e_idx)} does not match {ORIG_E_HEX}!")
        logger.warning(f"found e bytes instead: {data[e_idx:e_idx+4].hex()}")
        
    # bak the original file just in case
    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
    if not backup_path.exists():
        logger.info(f"creating backup at {backup_path.name}")
        shutil.copy2(file_path, backup_path)
        
    # pathc n
    data[n_idx:n_idx+128] = new_n_bytes
    
    # patch e
    data[e_idx:e_idx+4] = new_e_bytes
    
    # here we go
    with open(file_path, "wb") as f:
        f.write(data)
        
    logger.info(f"successfully patched {file_path.name} at n_offset={hex(n_idx)}, e_offset={hex(e_idx)}")
    return True


def main():
    parser = argparse.ArgumentParser(description="ida pro 9.3 rsa pub key patcher")
    parser.add_argument("-n", "--new-n", required=True, help="new modulus n (hex string, le, 128 bytes/256 chars)")
    parser.add_argument("-e", "--new-e", default="01000100", help="new exponent e (hex string, le, 4 bytes, default 65537/01000100)")
    parser.add_argument("-d", "--ida-dir", default=Path.home() / "meowida" / "IDA Professional 9.3.app" / "Contents" / "MacOS", type=Path, help="path to ida macos directory")
    
    args = parser.parse_args()
    
    new_n_hex = args.new_n.strip()
    if len(new_n_hex) != 256:
        logger.error(f"new N !!MUST BE!! exactly 256 hex char (128 bytes). goto {len(new_n_hex)}")
        sys.exit(1)
        
    new_e_hex = args.new_e.strip()
    if len(new_e_hex) != 8:
        logger.error(f"new E !!MUST BE!! exactly 8 hex char (4 bytes). got {len(new_e_hex)}")
        sys.exit(1)
        
    try:
        new_n_bytes = bytes.fromhex(new_n_hex)
        new_e_bytes = bytes.fromhex(new_e_hex)
    except ValueError as e:
        logger.error(f"invalid hex string provided: {e}")
        sys.exit(1)
        
    ida_dir = args.ida_dir
    
    targets = [
        ida_dir / "libida.dylib",
        ida_dir / "libida32.dylib",
    ]
    
    success_count = 0
    for target in targets:
        if patch_library(target, new_n_bytes, new_e_bytes):
            success_count += 1
            
    if success_count == len(targets):
        logger.info("all targets patched successfully! :3 youre ready to go. (─‿‿─)")
    else:
        logger.warning(f"patched {success_count}/{len(targets)} targets")

if __name__ == "__main__":
    main()