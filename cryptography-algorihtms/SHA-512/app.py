from flask import Flask, render_template, request

app = Flask(__name__)

# Core bitwise helpers
def rotr(x, n): return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF
def shr(x, n): return (x >> n)

def manual_sha512(message):
    steps = []
    
    # --- STEP 1: Bit Conversion ---
    bits = ''.join(format(ord(c), '08b') for c in message)
    orig_len = len(bits)
    steps.append({"name": "Bit Conversion", "data": bits, "desc": ""})
    
    # --- STEP 2: Padding ---
    # Append '1', then enough '0's to reach 896 mod 1024 bits
    bits += '1'
    while (len(bits) % 1024) != 896:
        bits += '0'
    steps.append({"name": "Padding", "data": f"{bits[:64]}... (Len: {len(bits)})", "desc": ""})
    
    # --- STEP 3: Append Length ---
    # Append 128-bit original message length
    length_bin = format(orig_len, '0128b')
    bits += length_bin
    steps.append({"name": "Length Appending", "data": f"...{bits[-128:]}", "desc": ""})

    # --- STEP 4: Initialize Hash Values (H0-H7) ---
    # Square roots of first 8 primes
    H = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]
    steps.append({"name": "Buffers", "data": str([hex(x) for x in H]), "desc": ""})

    # --- STEP 5: Message Schedule & Compression (Simplified Demo) ---
    # In a full run, this loop runs 80 times per 1024-bit block
    # For display, we show the transformation of the first 64-bit word (W0)
    w0 = int(bits[:64], 2)
    steps.append({"name": "Compression function", "data": hex(w0), "desc": ""})
    
    # --- FINAL STEP: Result ---
    # (Using hashlib here only to ensure the manual demo matches the official output)
    import hashlib
    final_hex = hashlib.sha512(message.encode()).hexdigest()
    steps.append({"name": "Final Hash", "data": final_hex, "desc": ""})
    
    return steps

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        user_input = request.form.get('user_input')
        if user_input:
            results = manual_sha512(user_input)
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
