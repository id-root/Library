
## Side Quest 4 - Decryption Key Analysis

To begin this side quest, download the **malicious HTA file** from the official TryHackMe room:

> https://tryhackme.com/room/htapowershell-aoc2025-p2l5k8j1h4

This HTA file implements a **multi-stage obfuscation and payload delivery chain** designed to evade casual inspection. Each stage progressively reveals the next layer of the payload.

### Obfuscation Stages Breakdown

### Stage 1 - VBScript (HTA Layer)
- The HTA file embeds **VBScript** code.
- A PowerShell payload is split into multiple strings and stored in the variable `p`.
- These strings are concatenated at runtime to form a **Base64-encoded PowerShell script**, hiding the real logic from static analysis.

### Stage 2 - PowerShell Loader
- Once decoded, the PowerShell script defines:
  - An **XOR key** (`$k = 23`)
  - A Base64-encoded blob (`$d`) containing encrypted data
- The script decodes the Base64 blob and applies an XOR operation using the key to recover the original payload.

### Stage 3 - XOR-Decrypted Payload
- The decrypted output begins with the PNG magic bytes (`89 50 4E 47 0D 0A 1A 0A`), that confirm us that the payload is an image.
- This PNG file is concealed using a **single-byte XOR cipher** with key `23`.

```python
import base64
import re

# ============================================================
# BANNER
# ============================================================
BANNER = r"""
 ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
 ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
 ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
 ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
 ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
 ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
"""
print(BANNER)

# ============================================================
# STEP 1: Read the malicious HTA file
# ============================================================
print("STEP 1: Reading the HTA file...")
with open('NorthPolePerformanceReview.hta', 'r', encoding='utf-8') as f:
    content = f.read()
print("✓ File loaded successfully\n")

# ============================================================
# STEP 2: Extract Base64-encoded PowerShell payload
# ============================================================
print("STEP 2: Extracting Base64 payload from VBScript...")

start_marker = 'p = "'
end_marker = 'Set fso'

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx == -1 or end_idx == -1:
    raise RuntimeError("Could not find Base64 payload markers")

base64_section = content[start_idx:end_idx]
quoted_strings = re.findall(r'"([^"]+)"', base64_section)
full_base64 = ''.join(quoted_strings)

print(f"✓ Extracted {len(full_base64)} characters of Base64 data\n")

# ============================================================
# STEP 3: Decode Base64 to reveal PowerShell script
# ============================================================
print("STEP 3: Decoding Base64 to PowerShell script...")
try:
    decoded_ps = base64.b64decode(full_base64).decode('utf-8')
except Exception as e:
    raise RuntimeError(f"Base64 decode failed: {e}")

print(f"✓ Decoded to {len(decoded_ps)} characters of PowerShell")
print("\nFirst 300 characters of PowerShell:")
print("-" * 60)
print(decoded_ps[:300])
print("-" * 60 + "\n")

# ============================================================
# STEP 4: Extract XOR key and encrypted data
# ============================================================
print("STEP 4: Extracting XOR key and encrypted data...")

lines = decoded_ps.splitlines()

key_lines = [l for l in lines if '$k=' in l]
if not key_lines:
    raise RuntimeError("XOR key not found")

xor_key = int(key_lines[0].split('=')[1].strip())
print(f"✓ XOR Key found: {xor_key}")

data_lines = [l for l in lines if "$d='" in l]
if not data_lines:
    raise RuntimeError("Encrypted data not found")

data_line = data_lines[0]
encrypted_b64 = data_line.split("'", 1)[1].rsplit("'", 1)[0]

print(f"✓ Encrypted data extracted: {len(encrypted_b64)} characters\n")

# ============================================================
# STEP 5: Decode encrypted Base64 data
# ============================================================
print("STEP 5: Decoding encrypted Base64 data...")
try:
    encrypted_bytes = base64.b64decode(encrypted_b64)
except Exception as e:
    raise RuntimeError(f"Encrypted Base64 decode failed: {e}")

print(f"✓ Decoded to {len(encrypted_bytes)} bytes\n")

# ============================================================
# STEP 6: XOR decrypt the data
# ============================================================
print("STEP 6: Performing XOR decryption...")
print(f"   XOR key: {xor_key}")

decrypted_bytes = bytearray(b ^ xor_key for b in encrypted_bytes)

print(f"✓ Decrypted {len(decrypted_bytes)} bytes\n")

# ============================================================
# STEP 7: Verify file type and save
# ============================================================
print("STEP 7: Verifying file type and saving output...")

png_signature = b'\x89PNG\r\n\x1a\n'
if decrypted_bytes.startswith(png_signature):
    print("✓ PNG signature verified")
else:
    print("⚠ Warning: Output does not match PNG signature")

output_filename = "decrypted_image.png"
with open(output_filename, 'wb') as f:
    f.write(decrypted_bytes)

print(f"✓ File saved as '{output_filename}'\n")

# ============================================================
# STEP 8: Summary
# ============================================================
print("=" * 60)
print("🎯 DECRYPTION COMPLETE")
print("=" * 60)
print(f"""
📊 Statistics:
   - HTA size           : {len(content)} bytes
   - Base64 payload size : {len(full_base64)} chars
   - PowerShell size     : {len(decoded_ps)} chars
   - Encrypted bytes     : {len(encrypted_bytes)}
   - Output size         : {len(decrypted_bytes)}

🔑 Key:
   - XOR key             : {xor_key}
   - Malicious domain    : perf.king-malhare[.]com
   - Output file         : {output_filename}

💡 Next step:
   Open '{output_filename}' to view the decrypted payload
""")

```

### Output
```bash
 > python3 dec.py 

 ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
 ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
 ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
 ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
 ██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
 ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   

STEP 1: Reading the HTA file...
✓ File loaded successfully

STEP 2: Extracting Base64 payload from VBScript...
✓ Extracted 745228 characters of Base64 data

STEP 3: Decoding Base64 to PowerShell script...
✓ Decoded to 558920 characters of PowerShell

First 300 characters of PowerShell:
------------------------------------------------------------
$h=$env:COMPUTERNAME
$u=$env:USERNAME
$k=23
$d='nkdZUBodDR0XFxcaXl9TRRcXFYsXFxS/HxEXFxdrwDO9Fxc3F15TVkNvzfuqbo8zcGKw7Ik4JXy4/UKqvqzCzU1cfH46Hx6Wz/ZtJ5EWdGSq9nr3GZwQD5t2ryH3fGwRe3T05nl0DHSY0M8U0Xe50Hd7FBUWVR9ef8jHzUz6Qo6CXGvw6QYGjkhrDk7KZ0xV126IEEOCAg4ODgYK5pyk6xkPkXYPkXYPkXYPkXYPkXYPkXYPkXYPkXYPkXYP
------------------------------------------------------------

STEP 4: Extracting XOR key and encrypted data...
✓ XOR Key found: 23
✓ Encrypted data extracted: 558664 characters

STEP 5: Decoding encrypted Base64 data...
✓ Decoded to 418996 bytes

STEP 6: Performing XOR decryption...
   XOR key: 23
✓ Decrypted 418996 bytes

STEP 7: Verifying file type and saving output...
✓ PNG signature verified
✓ File saved as 'decrypted_image.png'

============================================================
🎯 DECRYPTION COMPLETE
============================================================

📊 Statistics:
   - HTA size           : 795747 bytes
   - Base64 payload size : 745228 chars
   - PowerShell size     : 558920 chars
   - Encrypted bytes     : 418996
   - Output size         : 418996

🔑 Key:
   - XOR key             : 23
   - Malicious domain    : perf.king-malhare[.]com
   - Output file         : decrypted_image.png

💡 Next step:
   Open 'decrypted_image.png' to view the decrypted payload
```

### Flow Diagram. 
```text
NorthPolePerformanceReview.hta (malicious HTA)
    ↓
[VBScript extracts Base64]
    ↓
Base64 String (745,228 chars)
    ↓
[Base64 Decode]
    ↓
PowerShell Script (contains $k=23 and $d='...')
    ↓
[Extract encrypted data]
    ↓
Encrypted Base64 Data
    ↓
[Base64 Decode]
    ↓
Encrypted Bytes (418,996 bytes)
    ↓
[XOR with key 23]
    ↓
Decrypted PNG Image (668×936 pixels)
    ↓
Key for Breach-Blocker
```

### The Decrypted Image
![](10-Write-ups/BreachBlocker-Unlocker/egg.png)

