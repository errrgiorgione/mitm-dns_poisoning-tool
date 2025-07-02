from flask import Flask, redirect

app = Flask(__name__)

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def home(path):
    return redirect("your-website")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=80)
