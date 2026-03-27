from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/patient")
def patient():
    return render_template("patient.html")

@app.route("/device")
def device():
    return render_template("device.html")

@app.route("/logs")
def logs():
    return render_template("logs.html")

if __name__ == "__main__":
    app.run(debug=True)