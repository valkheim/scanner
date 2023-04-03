import argparse

import flask

from scanner.analyse import (
    get_last_results,
    get_results,
    handle_submitted_file,
    run_extractors,
)

gui = flask.Blueprint("gui", __name__, url_prefix="/")


@gui.route("/", methods=["GET"])
def index():
    last_results = get_last_results()
    return flask.render_template("index.html", last_results=last_results)


@gui.route("/r/<hash>", methods=["GET"])
def result(hash):
    results = get_results(hash)
    return flask.render_template("index.html", results=results)


@gui.route("/a/<hash>")
def analyse(hash):
    run_extractors(hash)
    return flask.redirect(flask.url_for("gui.result", hash=hash))


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
