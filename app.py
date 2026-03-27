from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'ab!hsaj@jknasdjna"jkwbdjkas@@'  # Required for session and flash messages

USERS = {
    "admin1": {
        "password": "admin123",
        "role": "Admin"
    },
    "doctor1": {
        "password": "doc123",
        "role": "Doctor"
    },
    "nurse1": {
        "password": "nurse123",
        "role": "Nurse"
    }
}

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = USERS.get(username)

        if not user:
            flash("Invalid username.", "danger")
            return redirect(url_for("login"))

        if user["password"] != password:
            flash("Invalid password.", "danger")
            return redirect(url_for("login"))

        session["username"] = username
        session["role"] = user["role"]

        flash(f"Login successful. Welcome {username} ({user['role']}).", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"]
    )

@app.route("/patient")
def patient():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    return render_template("patient.html", role=session["role"])


@app.route("/device")
def device():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    return render_template("device.html", role=session["role"])


@app.route("/logs")
def logs():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    if session["role"] != "Admin":
        flash("Access denied. Admin only.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("logs.html", role=session["role"])

if __name__ == "__main__":
    app.run(debug=True)