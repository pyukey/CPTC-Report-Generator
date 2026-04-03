from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import os
import re
import shutil

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
PREWRITES_DIR = os.path.join(BASE_DIR, "prewrites")
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

FILE_FIELDS = [
    "cvs.txt",
    "ips.txt",
    "details.txt",
    "confirmation.txt",
    "impact.txt",
    "mitigation.txt",
    "references.txt"
]

RICH_TEXT_FIELDS = [
    "details.txt",
    "confirmation.txt",
    "impact.txt",
    "mitigation.txt",
    "references.txt",
]
IMAGE_REFERENCE_ATTR = "data-image-filename"


def get_findings():
    if not os.path.exists(FINDINGS_DIR):
        os.makedirs(FINDINGS_DIR, exist_ok=True)
    return sorted(
        d for d in os.listdir(FINDINGS_DIR)
        if os.path.isdir(os.path.join(FINDINGS_DIR, d))
    )


def init_finding_structure(name):
    finding_path = os.path.join(FINDINGS_DIR, name)
    os.makedirs(finding_path, exist_ok=True)
    for fname in FILE_FIELDS:
        fpath = os.path.join(finding_path, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("")
    return finding_path

def get_prewrites():
    if not os.path.exists(PREWRITES_DIR):
        return []
    return sorted(
        d for d in os.listdir(PREWRITES_DIR)
        if os.path.isdir(os.path.join(PREWRITES_DIR, d))
    )

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def get_finding_path(finding_name):
    return os.path.join(FINDINGS_DIR, finding_name)


def read_finding_file(finding_path, filename):
    fpath = os.path.join(finding_path, filename)
    if not os.path.exists(fpath):
        return ""
    with open(fpath, "r", encoding="utf-8") as f:
        return f.read()


def write_finding_file(finding_path, filename, content):
    fpath = os.path.join(finding_path, filename)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content or "")


def image_reference_pattern(filename):
    escaped_filename = re.escape(filename)
    return re.compile(
        rf"<figure\b[^>]*\b{IMAGE_REFERENCE_ATTR}=(['\"]){escaped_filename}\1[^>]*>.*?</figure>",
        re.IGNORECASE | re.DOTALL,
    )


def get_image_references(finding_name, filename):
    finding_path = get_finding_path(finding_name)
    references = []
    pattern = image_reference_pattern(filename)

    for field in RICH_TEXT_FIELDS:
        content = read_finding_file(finding_path, field)
        count = len(pattern.findall(content))
        if count:
            references.append({
                "field": field,
                "count": count,
            })

    return references


def remove_image_references_everywhere(finding_name, filename):
    finding_path = get_finding_path(finding_name)
    pattern = image_reference_pattern(filename)
    removed = []

    for field in RICH_TEXT_FIELDS:
        content = read_finding_file(finding_path, field)
        updated_content, replacements = pattern.subn("", content)
        if replacements:
            updated_content = re.sub(r"(\s*<(div|p)><br></\2>\s*){3,}", "<div><br></div><div><br></div>", updated_content)
            write_finding_file(finding_path, field, updated_content.strip())
            removed.append({
                "field": field,
                "count": replacements,
            })

    return removed

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/prewrites", methods=["GET"])
def list_prewrites():
    return jsonify({"prewrites": get_prewrites()})

@app.route("/api/prewrites/<prewrite_name>", methods=["GET"])
def get_prewrite(prewrite_name):
    if prewrite_name not in get_prewrites():
        return jsonify({"error": "Prewrite not found"}), 404

    prewrite_path = os.path.join(PREWRITES_DIR, prewrite_name)
    data = {}
    for fname in FILE_FIELDS:
        fpath = os.path.join(prewrite_path, fname)
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as f:
                data[fname] = f.read()
        else:
            data[fname] = ""

    return jsonify({"name": prewrite_name, "files": data})

@app.route("/api/findings", methods=["GET"])
def list_findings():
    return jsonify({"findings": get_findings()})


@app.route("/api/findings", methods=["POST"])
def create_finding():
    data = request.get_json(force=True)
    name = data.get("name", "").strip()

    if not name:
        return jsonify({"error": "Finding name is required"}), 400

    if "/" in name or "\\" in name:
        return jsonify({"error": "Invalid finding name"}), 400

    finding_path = os.path.join(FINDINGS_DIR, name)
    if os.path.exists(finding_path):
        return jsonify({"error": "Finding already exists"}), 400

    init_finding_structure(name)
    return jsonify({"status": "ok", "name": name}), 201


@app.route("/api/findings/<finding_name>", methods=["GET"])
def get_finding(finding_name):
    if finding_name not in get_findings():
        return jsonify({"error": "Finding not found"}), 404

    finding_path = get_finding_path(finding_name)
    data = {}

    for fname in FILE_FIELDS:
        data[fname] = read_finding_file(finding_path, fname)

    return jsonify({
        "name": finding_name,
        "files": data
    })


@app.route("/api/findings/<finding_name>", methods=["PUT"])
def update_finding(finding_name):
    if finding_name not in get_findings():
        return jsonify({"error": "Finding not found"}), 404

    data = request.get_json(force=True)
    files = data.get("files", {})

    finding_path = get_finding_path(finding_name)

    for fname, content in files.items():
        if fname not in FILE_FIELDS:
            continue  # ignore unexpected keys
        write_finding_file(finding_path, fname, content)

    return jsonify({"status": "ok"})

@app.route("/api/findings/<finding_name>", methods=["DELETE"])
def delete_finding(finding_name):
    if finding_name not in get_findings():
        return jsonify({"error": "Finding not found"}), 404

    finding_path = get_finding_path(finding_name)
    shutil.rmtree(finding_path)
    return jsonify({"status": "ok"})

@app.route("/api/findings/<finding_name>/images", methods=["GET"])
def list_images(finding_name):
    if finding_name not in get_findings():
        return jsonify({"error": "Finding not found"}), 404
    
    images_dir = os.path.join(get_finding_path(finding_name), "images")
    if not os.path.exists(images_dir):
        return jsonify({"images": []})

    images = []
    for filename in os.listdir(images_dir):
        if allowed_image_file(filename):
            images.append(filename)

    return jsonify({"images": sorted(images)})

@app.route("/api/findings/<finding_name>/images", methods=["POST"])
def upload_image(finding_name):
    if finding_name not in get_findings():
        return jsonify({"error": "Finding not found"}), 404
    
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No image selected"}), 400

    if file and allowed_image_file(file.filename):
        filename = secure_filename(file.filename)
        images_dir = os.path.join(get_finding_path(finding_name), "images")
        os.makedirs(images_dir, exist_ok=True)

        filepath = os.path.join(images_dir, filename)
        file.save(filepath)
        return jsonify({"status": "ok", "filename": filename})

    return jsonify({"error": "Invalid image file"}), 400

@app.route("/api/findings/<finding_name>/images/<filename>", methods=["DELETE"])
def delete_image(finding_name, filename):
    if finding_name not in get_findings():
        return jsonify({"error": "Finding not found"}), 404

    images_dir = os.path.join(get_finding_path(finding_name), "images")
    filepath = os.path.join(images_dir, filename)
    delete_everywhere = request.args.get("delete_everywhere") == "1"

    if not os.path.exists(filepath):
        return jsonify({"error": "Image not found"}), 404

    references = get_image_references(finding_name, filename)
    if references and not delete_everywhere:
        return jsonify({
            "error": "Image is embedded in finding content",
            "references": references,
            "requires_confirmation": True,
        }), 409

    removed_references = []
    if delete_everywhere and references:
        removed_references = remove_image_references_everywhere(finding_name, filename)

    os.remove(filepath)
    return jsonify({
        "status": "ok",
        "removed_references": removed_references,
    })

@app.route("/api/findings/<finding_name>/images/<filename>", methods=["GET"])
def serve_image(finding_name, filename):
    images_dir = os.path.join(get_finding_path(finding_name), "images")
    return send_from_directory(images_dir, filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)

