from flask import Flask, request, render_template, jsonify
from waf_middleware import waf_check, load_rules
from log_parser import parse_logs

app = Flask(__name__)

# Load WAF rules on startup
load_rules()

@app.route("/")
def home():
    waf_check(request)
    return render_template("home.html")

@app.route("/test")
def test_form():
    return render_template("test_form.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    waf_check(request)
    return "Login successful! Request allowed."

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/dashboard-data")
def dashboard_data():
    data = parse_logs()
    return jsonify(data)

@app.route("/logs")
def logs_view():
    try:
        with open("logs/waf.log", "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        log_lines = []
    return render_template("logs.html", logs=log_lines)

@app.errorhandler(403)
def forbidden(e):
    return render_template("blocked.html", reason=e.description), 403

if __name__ == "__main__":
    app.run(debug=True)
