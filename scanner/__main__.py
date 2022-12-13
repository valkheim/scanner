import flask
import hashlib
import os
import json
import time
import datetime

from scanner.analyse import run_extractors, get_results

app = flask.Flask(__name__)
app.secret_key = "super secret key"

@app.route("/", methods=["GET"])
def index():
    import os
    last_results = {x:x for x in os.listdir("results")}
    last_results = []
    results_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "results"))
    for result in os.listdir(results_dir):
        infos_path = os.path.join(results_dir, result, "infos.json")
        if not os.path.exists(infos_path):
            continue

        with open(infos_path, "rt") as fh:
            infos = json.load(fh)
        
        print("infos=", infos)
        last_results += [infos]

    print(last_results)
    return flask.render_template("index.html", last_results=last_results)

@app.route("/r/<hash>", methods=["GET"])
def result(hash):
    dst_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "results", hash))
    results = get_results(dst_dir)
    return flask.render_template("index.html", result=results)

@app.route("/upload", methods=["POST"])
def upload():
    f = flask.request.files.get("file")
    # Copy file to results
    hash = hashlib.sha1(f.read()).hexdigest()
    f.seek(0)
    dst_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "results", hash))
    dst_file = os.path.join(dst_dir, f.filename)
    if not os.path.isdir(dst_dir):
        os.mkdir(dst_dir)
        f.save(dst_file)

    # Write analysis infos
    with open(os.path.join(dst_dir, "infos.json"), "wt") as fh:
        infos = {
            "filename": f.filename,
            "sha1": hash,
            "last_update": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        fh.write(json.dumps(infos))

    # Analyse file
    run_extractors(dst_file)
    return flask.redirect(flask.url_for("result", hash=hash))

def main():
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.debug = True
    app.run()
    flask.session.clear()

if __name__ == "__main__":
    main()
