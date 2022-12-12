import flask

app = flask.Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return flask.render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload(request):
    f = request.files.get("file")
    print(f)
    f.save(f.filename)

def main():
    app.run()

if __name__ == "__main__":
    main()
