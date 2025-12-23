import os
import json
import csv
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from PIL import Image
from geopy.geocoders import Nominatim
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ================================================================
#                        LOAD PUBLIC KEY
# ================================================================
with open("public_key.pem", "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())


# ================================================================
#                    SIGNATURE VERIFICATION
# ================================================================
def verify_signature(product):
    signature_hex = product["signature"]
    signature_bytes = bytes.fromhex(signature_hex)

    signed_content = {
        "product_id": product["product_id"],
        "name": product["name"],
        "batch": product["batch"],
        "date": product["date"]
    }

    data_bytes = json.dumps(signed_content, sort_keys=True).encode()

    try:
        PUBLIC_KEY.verify(
            signature_bytes,
            data_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False


# ================================================================
#                    MICRO PATTERN VERIFICATION
# ================================================================
def verify_micro_pattern(qr_img, product_id, batch):
    seed = product_id + batch
    digest = hashlib.sha256(seed.encode()).digest()
    bit_stream = ''.join(f"{byte:08b}" for byte in digest)

    pixels = qr_img.load()
    width, height = qr_img.size

    box_size = 5   # MUST match generator box_size
    modules = width // box_size

    bit_index = 0
    mismatches = 0
    checked = 0

    for y in range(4, modules - 4):
        for x in range(4, modules - 4):

            if (x + y) % 3 != 0:
                continue

            if bit_index >= len(bit_stream):
                break

            bit = bit_stream[bit_index]
            bit_index += 1

            x0 = x * box_size
            y0 = y * box_size

            r, g, b = pixels[x0 + 1, y0 + 1]
            is_black = r < 128

            if bit == "1" and is_black:
                checked += 1

                dot_x = x0 + box_size - 3
                dot_y = y0 + box_size - 3

                r2, g2, b2 = pixels[dot_x, dot_y]
                if not (r2 > 200 and g2 > 200 and b2 > 200):
                    mismatches += 1

    if checked == 0:
        return False

    accuracy = 100 * (checked - mismatches) / checked
    return accuracy > 85


# ================================================================
#                COUNTRY VERIFICATION (GEOLOCATION)
# ================================================================
def check_country(lat, lng):
    try:
        geolocator = Nominatim(user_agent="qr_verifier")
        location = geolocator.reverse(f"{lat}, {lng}", language="en")

        if not location:
            return "Unknown"

        return location.raw["address"].get("country", "Unknown")

    except:
        return "Unknown"


# ================================================================
#                   CSV LOGGING FUNCTION
# ================================================================
def log_scan(product_id, batch, country, result):
    file_exists = os.path.isfile("scan_logs.csv")

    with open("scan_logs.csv", "a", newline="") as f:
        writer = csv.writer(f)

        # Add header once
        if not file_exists:
            writer.writerow(["Product ID", "Batch", "Country", "Timestamp", "Result"])

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([product_id, batch, country, timestamp, result])


# ================================================================
#                        FLASK BACKEND
# ================================================================
app = Flask(__name__, template_folder="templates")


@app.route("/scan", methods=["GET"])
def scan_page():
    pid = request.args.get("pid")
    batch = request.args.get("batch")

    return render_template("scan.html", pid=pid, batch=batch)


@app.route("/verify", methods=["POST"])
def verify_qr():
    pid = request.form.get("pid")
    batch = request.form.get("batch")

    # Load product from backend storage
    with open("product.json") as f:
        product_data = json.load(f)

    # QR image (micropattern requires actual image upload)
    qr_image_file = request.files.get("qr_image")
    if qr_image_file is None:
        log_scan(pid, batch, "Unknown", "missing-qr")
        return jsonify({"status": "error", "message": "QR image missing"}), 400

    qr_img = Image.open(qr_image_file).convert("RGB")

    # Signature verification
    if not verify_signature(product_data):
        log_scan(pid, batch, "Unknown", "fake-signature")
        return jsonify({"status": "fake", "reason": "Invalid signature"})

    # Micro-pattern verification
    if not verify_micro_pattern(qr_img, pid, batch):
        log_scan(pid, batch, "Unknown", "micro-pattern-mismatch")
        return jsonify({"status": "suspect", "reason": "Micro-pattern mismatch"})

    # GPS data
    lat = request.form.get("lat")
    lng = request.form.get("lng")
    accuracy = request.form.get("accuracy")

    # Country lookup
    country = check_country(lat, lng)

    # Suspicious if scanned outside Sri Lanka
    if country != "Sri Lanka":
        log_scan(pid, batch, country, "suspect-location")
        return jsonify({
            "status": "suspect-location",
            "country_detected": country,
            "message": "QR scanned from outside Sri Lanka. Suspicious activity detected."
        })

    # Everything passed → authentic
    log_scan(pid, batch, country, "authentic")

    return jsonify({
        "status": "authentic",
        "country_detected": country,
        "gps": {
            "lat": lat,
            "lng": lng,
            "accuracy": accuracy
        },
        "message": "Verification successful"
    })


if __name__ == "__main__":
    app.run(port=5000, debug=True)
