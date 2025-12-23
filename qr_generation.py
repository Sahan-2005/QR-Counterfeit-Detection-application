import os
import json
import hashlib
import qrcode
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ================================================================
#                 KEY GENERATION (ONE TIME)
# ================================================================
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("Keys generated successfully!")


def load_private_key():
    with open("private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)


# ================================================================
#              SIGN PRODUCT USING RSA DIGITAL SIGNATURE
# ================================================================
def sign_product_data(product):
    private_key = load_private_key()

    content = {
        "product_id": product["product_id"],
        "name": product["name"],
        "batch": product["batch"],
        "date": product["date"]
    }

    data_bytes = json.dumps(content, sort_keys=True).encode()

    signature = private_key.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature.hex()


# ================================================================
#                   MICRO PATTERN EMBEDDING
# ================================================================
def embed_micro_pattern(img, matrix, box_size, seed):
    draw = ImageDraw.Draw(img)

    digest = hashlib.sha256(seed.encode()).digest()
    bit_stream = ''.join(f"{byte:08b}" for byte in digest)

    size = len(matrix)
    bit_index = 0

    for y in range(4, size - 4):
        for x in range(4, size - 4):
            if (x + y) % 3 != 0:
                continue

            if bit_index >= len(bit_stream):
                return

            bit = bit_stream[bit_index]
            bit_index += 1

            if bit == "1" and matrix[y][x]:
                x0 = x * box_size + box_size - 3
                y0 = y * box_size + box_size - 3
                draw.rectangle((x0, y0, x0 + 1, y0 + 1), fill="white")


# ================================================================
#                   QR CODE CREATION (URL ONLY)
# ================================================================
def create_qr_code(verify_url, micro_text, pattern_seed):
    qr = qrcode.QRCode(
        version=6,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=5,
        border=4
    )

    qr.add_data(verify_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 6)
    except:
        font = ImageFont.load_default()

    draw.text((10, img.size[1] - 15), micro_text, font=font, fill="black")

    matrix = qr.get_matrix()
    embed_micro_pattern(img, matrix, qr.box_size, pattern_seed)

    img.save("product_qr.png")
    print(" QR Code saved as product_qr.png")


# ================================================================
#                        MAIN
# ================================================================
def main():
    if not os.path.exists("private_key.pem"):
        generate_keys()

    # Product metadata stored in secure backend
    product = {
        "product_id": "PID-998877",
        "name": "Limited Edition Hoodie",
        "batch": "BATCH-55X",
        "date": "2025-01-07"
    }

    # Generate signature once and store securely
    product["signature"] = sign_product_data(product)

    with open("product.json", "w") as f:
        json.dump(product, f, indent=4)

    print("\n Product Data Saved:")
    print(json.dumps(product, indent=4))

    # URL embedded in QR (Option 2 secure)
    verify_url = f"http://localhost:5000/scan?pid={product['product_id']}&batch={product['batch']}"
    print("Generated URL:", verify_url)


    pattern_seed = product["product_id"] + product["batch"]

    create_qr_code(verify_url, "AUTH-LINK", pattern_seed)

    print("\n QR Ready.\n")


if __name__ == "__main__":
    main()
