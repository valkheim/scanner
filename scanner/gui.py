import argparse

import flask

from scanner.analyse import (
    del_result,
    get_last_results,
    get_result,
    handle_submitted_file,
    read_result_infos,
    run_extractors,
)
from scanner.utils import archive, resolve_extractor_path

gui = flask.Blueprint("gui", __name__, url_prefix="/")


@gui.route("/", methods=["GET"])
def index():
    last_results = get_last_results()
    return flask.render_template("index.html", last_results=last_results)


@gui.route("/r/<hash>", methods=["GET"])
def result(hash):
    results = get_result(hash)
    return flask.render_template("analysis.html", results=results)


@gui.route("/a/<hash>")
def analyse(hash):
    if (
        extractor_result_path := flask.request.args.get("extractor")
    ) is not None:
        extractor_path = resolve_extractor_path(extractor_result_path)
        run_extractors(hash, extractor_abspaths_whitelist=[extractor_path])
    else:
        run_extractors(hash)

    return flask.redirect(flask.url_for("gui.result", hash=hash))


@gui.route("/d/<hash>", methods=["GET"])
def delete(hash):
    del_result(hash)
    return flask.redirect(flask.url_for("gui.index"))


@gui.route("/x/<hash>")
def export(hash):
    infos = read_result_infos(hash)
    if not infos:
        print("[-] no infos")
        return flask.redirect(flask.url_for("gui.index"))

    archive_path = archive(hash, infos)
    return flask.send_file(archive_path)


@gui.route("/upload", methods=["POST"])
def upload():
    file = flask.request.files.get("file")
    hash = handle_submitted_file(file, file.filename)
    return flask.redirect(flask.url_for("gui.analyse", hash=hash))


def run(args: argparse.Namespace) -> int:
    app = flask.Flask(__name__)

    # setup config
    app.secret_key = "super secret key"
    app.jinja_env.auto_reload = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.debug = True

    app.register_blueprint(gui)

    app.run()
    return 0
