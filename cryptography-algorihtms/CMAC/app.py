from flask import Flask, render_template, request

app = Flask(__name__)

# Constants for 128-bit blocks
BLOCK_SIZE = 16
Rb = 0x00000000000000000000000000000087  # Standard constant for 128-bit CMAC

def bit_shift_left(val_bytes):
    """Shifts a 16-byte array left by 1 bit."""
    int_val = int.from_bytes(val_bytes, 'big')
    shifted = (int_val << 1) & (2**128 - 1)
    return shifted.to_bytes(16, 'big')

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def mock_encrypt(key, data):
    """A simplified bitwise cipher to replace standard AES for manual demo."""
    return xor_bytes(data, key)

def generate_subkeys(key):
    """Step 1: Subkey Generation (K1, K2)"""
    L = mock_encrypt(key, b'\x00' * 16)
    
    # Generate K1
    msb_l = L[0] & 0x80
    K1 = bit_shift_left(L)
    if msb_l:
        K1 = xor_bytes(K1, Rb.to_bytes(16, 'big'))
        
    # Generate K2
    msb_k1 = K1[0] & 0x80
    K2 = bit_shift_left(K1)
    if msb_k1:
        K2 = xor_bytes(K2, Rb.to_bytes(16, 'big'))
    
    return K1, K2

def compute_cmac(key, message):
    steps = []
    K1, K2 = generate_subkeys(key)
    steps.append({"name": "Subkey Generation", "data": f"K1: {K1.hex()}, K2: {K2.hex()}", "desc": ""})

    # Step 2: Message Partitioning & Padding
    msg_len = len(message)
    n = (msg_len + BLOCK_SIZE - 1) // BLOCK_SIZE if msg_len > 0 else 1
    blocks = [message[i*BLOCK_SIZE : (i+1)*BLOCK_SIZE] for i in range(n)]
    
    last_block = blocks[-1]
    is_complete = (len(last_block) == BLOCK_SIZE)
    
    if is_complete:
        M_last = xor_bytes(last_block, K1)
        steps.append({"name": "Block ", "data": M_last.hex(), "desc": ""})
    else:
        # Padding: 0x80 followed by zeros
        padding = b'\x80' + (b'\x00' * (BLOCK_SIZE - len(last_block) - 1))
        M_last = xor_bytes(last_block + padding, K2)
        steps.append({"name": "Padded Block", "data": M_last.hex(), "desc": ""})

    # Step 3: Chaining (CBC Mode)
    X = b'\x00' * 16
    for i in range(n - 1):
        Y = xor_bytes(X, blocks[i])
        X = mock_encrypt(key, Y)
        steps.append({"name": f"Round {i+1} Output", "data": X.hex(), "desc": f"Intermediate result after block {i+1}."})

    # Final Round
    tag = mock_encrypt(key, xor_bytes(X, M_last))
    steps.append({"name": "Final CMAC", "data": tag.hex(), "desc": ""})
    
    return steps

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        key = request.form.get('key').encode().ljust(16, b'\0')[:16]
        msg = request.form.get('message').encode()
        results = compute_cmac(key, msg)
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
