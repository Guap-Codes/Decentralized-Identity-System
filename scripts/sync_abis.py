#!/usr/bin/env python3
"""
ABI Synchronization Script

Automates:
1. Compiling Foundry smart contracts
2. Extracting ABIs from compiled artifacts
3. Copying ABIs to Rust service directory

Usage:
$ python scripts/sync_abis.py

Configuration:
- Set CONTRACTS_DIR and RUST_ABI_DIR at top of script
"""

import os
import json
import shutil
import subprocess
from pathlib import Path

# Configuration - Update these paths according to your project structure
CONTRACTS_DIR = Path("contracts")
RUST_ABI_DIR = Path("src/services/abi")
CONTRACTS_TO_COPY = ["CredentialRegistry", "DIDRegistry", "Paymaster"]

def compile_contracts():
    """Compile Foundry contracts using forge build"""
    print("🔨 Compiling smart contracts...")
    try:
        result = subprocess.run(
            ["forge", "build"],
            cwd=CONTRACTS_DIR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("✅ Contracts compiled successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Compilation failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print("❌ Foundry not installed. Please install Foundry: https://book.getfoundry.sh/getting-started/installation")
        return False

def copy_abis():
    """Copy ABIs from out/ directory to Rust service directory"""
    print("\n📂 Copying ABIs...")
    artifacts_dir = CONTRACTS_DIR / "out"
    files_copied = 0
    
    # Create destination directory if it doesn't exist
    RUST_ABI_DIR.mkdir(parents=True, exist_ok=True)
    
    for contract in CONTRACTS_TO_COPY:
        # Find contract JSON file (handles versioned directories)
        artifact_path = None
        for root, _, files in os.walk(artifacts_dir):
            for file in files:
                if file == f"{contract}.json":
                    artifact_path = Path(root) / file
                    break
            if artifact_path:
                break
        
        if not artifact_path or not artifact_path.exists():
            print(f"⚠️  Artifact not found for {contract}")
            continue
        
        # Extract ABI from artifact
        with open(artifact_path, 'r') as f:
            artifact = json.load(f)
            abi = artifact.get("abi", [])
        
        # Write ABI to destination
        dest_path = RUST_ABI_DIR / f"{contract}.json"
        with open(dest_path, 'w') as f:
            json.dump(abi, f, indent=2)
        
        print(f"• Copied {contract}.json ({len(abi)} items)")
        files_copied += 1
    
    print(f"✅ {files_copied}/{len(CONTRACTS_TO_COPY)} ABIs copied to {RUST_ABI_DIR}")

def main():
    print("\n" + "="*50)
    print("🛠️  Smart Contract ABI Synchronization")
    print("="*50)
    
    if compile_contracts():
        copy_abis()

if __name__ == "__main__":
    main()