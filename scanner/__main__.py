import flask

app = flask.Flask(__name__)
app.secret_key = "super secret key"

@app.route("/", methods=["GET"])
def index():
    import os
    last_results = {x:x for x in os.listdir("results")}
    return flask.render_template("index.html", last_results=last_results)

@app.route("/result/<id>", methods=["GET"])
def result(id):
    return flask.render_template("index.html", result=id)

@app.route("/upload", methods=["POST"])
def upload():
    f = flask.request.files.get("file")
    f.save("results/" + f.filename)
    # redirect to result page
    return flask.redirect(flask.url_for("result", id=f.filename))

def main():
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.debug = True
    app.run()
    flask.session.clear()

if __name__ == "__main__":
    main()
