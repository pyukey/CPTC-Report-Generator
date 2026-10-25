from flask import Flask, redirect, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import os
import re
import shutil
import datetime
import json

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FINDINGS_DIR = os.path.join(BASE_DIR, "findings")
PREWRITES_DIR = os.path.join(BASE_DIR, "prewrites")
OVERVIEW_DIR = os.path.join(BASE_DIR, "overviews")
APPENDIX_DIR = os.path.join(BASE_DIR, "appendix")
TOOLS_DIR = os.path.join(APPENDIX_DIR, "tools")
APPENDICES_DIR = os.path.join(APPENDIX_DIR, "entries")
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

FINDING_FIELDS = [
    "cvs.txt",
    "ips.txt",
    "details.txt",
    "confirmation.txt",
    "impact.txt",
    "mitigation.txt",
    "references.txt"
]

OVERVIEW_FIELDS = [
    "team-name.txt",
    "team-email.txt",
    "team-phone.txt",
    "client-name.txt",
    "start-time.txt",
    "end-time.txt",
    "report-time.txt",
    "short-scope.txt",
    "executive.txt",
    "rationale.txt",
    "goals.txt",
    "ai-workflow.txt",
    "ai-efficacy.txt",
    "scope.txt",
    "strengths.txt",
    "recommendations.txt"
]

RICH_TEXT_FIELDS = [
    "details.txt",
    "confirmation.txt",
    "impact.txt",
    "mitigation.txt",
    "references.txt",
]
IMAGE_REFERENCE_ATTR = "data-image-filename"


def list_files(path, wantDirs=False):
    if not os.path.exists(path):
        return []
    return sorted(
        d for d in os.listdir(path)
        if not wantDirs or os.path.isdir(os.path.join(path, d))
    )

def get_findings():
    return list_files(FINDINGS_DIR, True)

def get_prewrites():
    return list_files(PREWRITES_DIR)

def get_tools():
    return list_files(TOOLS_DIR)

def get_entries():
    return list_files(APPENDICES_DIR)

def init_finding_structure(name):
    finding_path = os.path.join(FINDINGS_DIR, name)
    os.makedirs(finding_path, exist_ok=True)
    for fname in FINDING_FIELDS:
        fpath = os.path.join(finding_path, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("")
    return finding_path

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def get_finding_path(finding_name):
    return os.path.join(FINDINGS_DIR, finding_name)


def read_file(finding_path, filename):
    fpath = os.path.join(finding_path, filename)
    if not os.path.exists(fpath):
        return ""
    with open(fpath, "r", encoding="utf-8") as f:
        return f.read()


def write_file(finding_path, filename, content):
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
        content = read_file(finding_path, field)
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
        content = read_file(finding_path, field)
        updated_content, replacements = pattern.subn("", content)
        if replacements:
            updated_content = re.sub(r"(\s*<(div|p)><br></\2>\s*){3,}", "<div><br></div><div><br></div>", updated_content)
            write_file(finding_path, field, updated_content.strip())
            removed.append({
                "field": field,
                "count": replacements,
            })

    return removed

@app.before_request
def log_request_info():
    now = datetime.datetime.now()
    match request.method:
        case 'GET': 
            if request.path == '/findings':
                print(f"[{now}] {request.remote_addr} is viewing the Findings page.")
            elif request.path == '/overviews':
                print(f"[{now}] {request.remote_addr} is viewing the Overviews page.")
            elif request.path.startswith('/api/findings/'):
                parts = request.path.split("/")
                if len(parts) == 4:
                    print(f"[{now}] {request.remote_addr} is viewing Finding: {parts[3]}")
            elif request.path.startswith('/api/prewrites/'):
                parts = request.path.split("/")
                if len(parts) == 4:
                    print(f"[{now}] {request.remote_addr} loaded Prewrite: {parts[3]}")
            elif request.path == '/api/appendix/tools':
                print(f"[{now}] {request.remote_addr} is loading the Appendix tools")
            elif request.path == '/api/appendix/entry':
                print(f"[{now}] {request.remote_addr} is loading the Appendix entries")
        case 'POST':
            if request.path.startswith('/api/findings'):
                parts = request.path.split("/")
                if len(parts) == 3:
                    print(f"[{now}] {request.remote_addr} created a new Finding")
                elif len(parts) == 5 and parts[4] == 'images':
                    print(f"[{now}] {request.remote_addr} uploaded an image to Finding: {parts[3]}")
        case 'PUT':
            if request.path.startswith('/api/findings/'):
                parts = request.path.split("/")
                if len(parts) == 4:
                    print(f"[{now}] {request.remote_addr} updated Finding: {parts[3]}")
            elif request.path == '/api/overviews':
                print(f"[{now}] {request.remote_addr} updated the Overviews")
            elif request.path == '/api/appendix/tools':
                print(f"[{now}] {request.remote_addr} updated the Appendix tools")
            elif request.path == '/api/appendix/entry':
                print(f"[{now}] {request.remote_addr} updated the Appendix entries")
        case 'DELETE':
            if request.path.startswith('/api/findings/'):
                parts = request.path.split("/")
                if len(parts) == 4:
                    print(f"[{now}] {request.remote_addr} deleted Finding: {parts[3]}")
                if len(parts) == 6 and parts[4] == 'images':
                    print(f"[{now}] {request.remote_addr} removed {parts[5]} from Finding: {parts[3]}")
            elif request.path.startswith('/api/appendix/tools/'):
                parts = request.path.split("/")
                print(f"[{now}] {request.remote_addr} deleted Appendix tool: {parts[4]}")
            elif request.path.startswith('/api/appendix/entry/'):
                parts = request.path.split("/")
                print(f"[{now}] {request.remote_addr} deleted Appendix entry: {parts[4]}")

@app.route("/")
def index():
    return redirect('/findings', code=302)

@app.route("/findings")
def findings():
    return render_template("findings.html")

@app.route("/overviews")
def overview():
    return render_template("overview.html")

@app.route("/appendix")
def appendix():
    return render_template("appendix.html")

@app.route("/api/prewrites", methods=["GET"])
def list_prewrites():
    return jsonify({"prewrites": get_prewrites()})

@app.route("/api/prewrites/<prewrite_name>", methods=["GET"])
def get_prewrite(prewrite_name):
    if prewrite_name not in get_prewrites():
        return jsonify({"error": "Prewrite not found"}), 404

    prewrite_path = os.path.join(PREWRITES_DIR, prewrite_name)
    data = {}
    for fname in FINDING_FIELDS:
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

    for fname in FINDING_FIELDS:
        data[fname] = read_file(finding_path, fname)

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
        if fname not in FINDING_FIELDS:
            continue  # ignore unexpected keys
        write_file(finding_path, fname, content)

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

@app.route("/api/overviews", methods=["GET"])
def get_overview():
    data = {}
    for fname in OVERVIEW_FIELDS:
        data[fname] = read_file(OVERVIEW_DIR, fname)

    return jsonify({
        "files": data
    })

@app.route("/api/overviews", methods=["PUT"])
def update_overview():
    data = request.get_json(force=True)
    files = data.get("files", {})

    for fname, content in files.items():
        if fname not in OVERVIEW_FIELDS:
            continue
        write_file(OVERVIEW_DIR, fname, content)
    return jsonify({"status": "ok"})

@app.route("/api/appendix/tools", methods=["GET"])
def get_tool():
    data = {}
    for fname in get_tools():
        data[fname.split('.')[0]] = json.loads(read_file(TOOLS_DIR, fname))
    return data

@app.route("/api/appendix/tools", methods=["PUT"])
def update_tools():
    data = request.get_json(force=True)
    files = data.get("files", {})

    for fname, content in files.items():
        write_file(TOOLS_DIR, f"{fname}.json", json.dumps(content))
    return jsonify({"status": "ok"})

@app.route("/api/appendix/tools/<tool_name>", methods=["DELETE"])
def delete_tools(tool_name):
    os.remove(os.path.join(TOOLS_DIR, f"{tool_name}.json"))
    return jsonify({"status": "ok"})

@app.route("/api/appendix/entry", methods=["GET"])
def get_appendix():
    data = {}
    for fname in get_entries():
        data[fname.split('.')[0]] = read_file(APPENDICES_DIR, fname)
    return data

@app.route("/api/appendix/entry", methods=["PUT"])
def update_appendix():
    data = request.get_json(force=True)
    files = data.get("files", {})

    for fname, content in files.items():
        write_file(APPENDICES_DIR, f"{fname}.txt", content)
    return jsonify({"status": "ok"})

@app.route("/api/appendix/entry/<appendix_name>", methods=["DELETE"])
def delete_appendix(appendix_name):
    os.remove(os.path.join(APPENDICES_DIR, f"{appendix_name}.txt"))
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=5001)

