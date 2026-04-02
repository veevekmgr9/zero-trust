from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "hospital_secret_key_123"

# Encryption setup
key = Fernet.generate_key()
cipher = Fernet(key)

# Demo users
USERS = {
    "admin1": {"password": "admin123", "role": "Admin"},
    "doctor1": {"password": "doc123", "role": "Doctor"},
    "nurse1": {"password": "nurse123", "role": "Nurse"}
}

PATIENTS = {
    "P001": {
        "name": "John Smith",
        "age": 45,
        "diagnosis": "Hypertension",
        "heart_rate": 82,
        "notes": "Requires regular blood pressure monitoring."
    },
    "P002": {
        "name": "Sarah Khan",
        "age": 32,
        "diagnosis": "Diabetes",
        "heart_rate": 76,
        "notes": "Needs insulin tracking and diet observation."
    }
}

IOT_DEVICES = {
    "Heart Monitor": {
        "device_id": "D001",
        "patient_id": "P001",
        "status": "Connected",
        "last_reading": "Heart Rate: 82 bpm"
    },
    "Wearable Sensor": {
        "device_id": "D002",
        "patient_id": "P002",
        "status": "Connected",
        "last_reading": "Glucose Level: Stable"
    },
    "Smart Infusion Pump": {
        "device_id": "D003",
        "patient_id": "P002",
        "status": "Connected",
        "last_reading": "Infusion running normally"
    }
}
# Trusted devices
TRUSTED_DEVICES = [
    "Heart Monitor",
    "Wearable Sensor",
    "Nurse Tablet",
    "Admin Workstation",
    "Smart Infusion Pump"
]

# Trusted IPs
TRUSTED_IPS = [
    "127.0.0.1",
    "192.168.1.10",
    "192.168.1.11"
]

# Role permissions
ROLE_PERMISSIONS = {
    "Admin": ["manage_users", "manage_devices", "manage_ips", "view_logs", "view_record"],
    "Doctor": ["view_record", "update_record"],
    "Nurse": ["view_record"]
}


def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            role TEXT,
            module_name TEXT,
            device_name TEXT,
            ip_address TEXT,
            requested_action TEXT,
            request_count INTEGER,
            user_input TEXT,
            attack_type TEXT,
            decision TEXT,
            reason TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_request(username, role, module_name, device_name, ip_address,
                requested_action, request_count, user_input,
                attack_type, decision, reason):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_logs
        (username, role, module_name, device_name, ip_address,
         requested_action, request_count, user_input,
         attack_type, decision, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        username, role, module_name, device_name, ip_address,
        requested_action, request_count, user_input,
        attack_type, decision, reason
    ))

    conn.commit()
    conn.close()


def detect_attack(user_input, ip_address, request_count):
    if "'" in user_input or " OR " in user_input.upper() or "--" in user_input:
        return "SQL Injection", "Potential SQL injection pattern detected."

    if "<script>" in user_input.lower():
        return "Cross-Site Scripting (XSS)", "Potential XSS payload detected."

    if ip_address not in TRUSTED_IPS:
        return "IP Spoofing / Untrusted Source", "IP address failed verification."

    if request_count > 100:
        return "Possible SYN Flood / Abnormal Traffic", "Abnormally high request volume detected."

    return "Normal", "No malicious pattern detected."


def zero_trust_verify(username, role, module_name, device_name, ip_address,
                      requested_action, request_count, user_input):
    if username not in USERS:
        return "Unknown User", "Deny", "User identity could not be verified."

    actual_role = USERS[username]["role"]
    if actual_role != role:
        return "Role Mismatch", "Deny", "Role does not match authenticated session."

    if device_name not in TRUSTED_DEVICES:
        return "Untrusted IoT Device", "Deny", "Device is not trusted under Zero Trust policy."

    if ip_address not in TRUSTED_IPS:
        return "IP Spoofing / Untrusted Source", "Deny", "IP address is not trusted."

    allowed_actions = ROLE_PERMISSIONS.get(role, [])
    if requested_action not in allowed_actions:
        return "Unauthorized Action", "Deny", "Role is not allowed to perform this action."

    attack_type, attack_reason = detect_attack(user_input, ip_address, request_count)
    if attack_type != "Normal":
        return attack_type, "Deny", attack_reason

    return "Normal", "Allow", "Request passed Zero Trust verification."


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

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE decision='Allow'")
    allowed_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE decision='Deny'")
    denied_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_logs WHERE attack_type!='Normal'")
    detected_attacks = cursor.fetchone()[0]

     # Decision stats
    cursor.execute("SELECT decision, COUNT(*) FROM security_logs GROUP BY decision")
    decision_rows = cursor.fetchall()

    # Attack stats
    cursor.execute("SELECT attack_type, COUNT(*) FROM security_logs GROUP BY attack_type")
    attack_rows = cursor.fetchall()

    conn.close()

    decision_labels = [row[0] for row in decision_rows]
    decision_values = [row[1] for row in decision_rows]

    attack_labels = [row[0] for row in attack_rows]
    attack_values = [row[1] for row in attack_rows]

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        total_requests=total_requests,
        allowed_requests=allowed_requests,
        denied_requests=denied_requests,
        detected_attacks=detected_attacks,
        decision_labels=decision_labels,
        decision_values=decision_values,
        attack_labels=attack_labels,
        attack_values=attack_values
    )


@app.route("/patient", methods=["GET", "POST"])
def patient():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    result = None
    encrypted_data = None
    decrypted_data = None
    displayed_patient = None

    if request.method == "POST":
        patient_id = request.form["patient_id"]
        device_name = request.form["device_name"]
        requested_action = request.form["requested_action"]
        request_count = int(request.form["request_count"])
        user_input = request.form["user_input"]

        simulated_ip = request.form.get("simulated_ip", "").strip()
        ip_address = simulated_ip if simulated_ip else request.remote_addr

        attack_type, decision, reason = zero_trust_verify(
            username=session["username"],
            role=session["role"],
            module_name="Patient Module",
            device_name=device_name,
            ip_address=ip_address,
            requested_action=requested_action,
            request_count=request_count,
            user_input=user_input
        )

        if decision == "Allow" and patient_id in PATIENTS:
            displayed_patient = PATIENTS[patient_id]

            patient_text = f"""
                Patient ID: {patient_id}
                Name: {displayed_patient['name']}
                Age: {displayed_patient['age']}
                Diagnosis: {displayed_patient['diagnosis']}
                Heart Rate: {displayed_patient['heart_rate']}
                Notes: {displayed_patient['notes']}
            """.strip()

            encrypted_data = cipher.encrypt(patient_text.encode()).decode()
            decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()

        log_request(
            username=session["username"],
            role=session["role"],
            module_name="Patient Module",
            device_name=device_name,
            ip_address=ip_address,
            requested_action=requested_action,
            request_count=request_count,
            user_input=user_input,
            attack_type=attack_type,
            decision=decision,
            reason=reason
        )

        result = {
            "patient_id": patient_id,
            "device_name": device_name,
            "ip_address": ip_address,
            "requested_action": requested_action,
            "attack_type": attack_type,
            "decision": decision,
            "reason": reason
        }

    return render_template(
        "patient.html",
        role=session["role"],
        result=result,
        encrypted_data=encrypted_data,
        decrypted_data=decrypted_data,
        displayed_patient=displayed_patient,
        patients=PATIENTS
    )


@app.route("/device", methods=["GET", "POST"])
def device():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    result = None
    displayed_device = None
    linked_patient = None
    encrypted_device_data = None
    decrypted_device_data = None

    if request.method == "POST":
        device_name = request.form["device_name"]
        requested_action = request.form["requested_action"]
        request_count = int(request.form["request_count"])
        user_input = request.form["user_input"]
        patient_id = request.form.get("patient_id")

        simulated_ip = request.form.get("simulated_ip", "").strip()
        ip_address = simulated_ip if simulated_ip else request.remote_addr

        attack_type, decision, reason = zero_trust_verify(
            username=session["username"],
            role=session["role"],
            module_name="Device Module",
            device_name=device_name,
            ip_address=ip_address,
            requested_action=requested_action,
            request_count=request_count,
            user_input=user_input
        )

        if decision == "Allow" and device_name in IOT_DEVICES:
            displayed_device = IOT_DEVICES[device_name]
            patient_id = PATIENTS.get(patient_id)

            device_text = f"""
Device Name: {device_name}
Device ID: {displayed_device['device_id']}
Status: {displayed_device['status']}
Patient ID: {displayed_device['patient_id']}
Last Reading: {displayed_device['last_reading']}
            """.strip()

            encrypted_device_data = cipher.encrypt(device_text.encode()).decode()
            decrypted_device_data = cipher.decrypt(encrypted_device_data.encode()).decode()

        log_request(
            username=session["username"],
            role=session["role"],
            module_name="Device Module",
            device_name=device_name,
            ip_address=ip_address,
            requested_action=requested_action,
            request_count=request_count,
            user_input=user_input,
            attack_type=attack_type,
            decision=decision,
            reason=reason
        )

        result = {
            "device_name": device_name,
            "ip_address": ip_address,
            "requested_action": requested_action,
            "attack_type": attack_type,
            "decision": decision,
            "reason": reason
        }

    return render_template(
        "device.html",
        role=session["role"],
        result=result,
        displayed_device=displayed_device,
        encrypted_device_data=encrypted_device_data,
        decrypted_device_data=decrypted_device_data,
        devices=IOT_DEVICES,
        patients=PATIENTS
    )

@app.route("/logs")
def logs():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    if session["role"] != "Admin":
        flash("Access denied. Admin only.", "danger")
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, role, module_name, device_name, ip_address,
               requested_action, attack_type, decision, reason
        FROM security_logs
        ORDER BY id DESC
    """)
    logs_data = cursor.fetchall()
    conn.close()

    return render_template("logs.html", role=session["role"], logs_data=logs_data)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    if session["role"] != "Admin":
        flash("Access denied. Admin only.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        new_ip = request.form.get("new_ip", "").strip()
        new_device = request.form.get("new_device", "").strip()

        if new_ip:
            if new_ip not in TRUSTED_IPS:
                TRUSTED_IPS.append(new_ip)
                flash(f"Trusted IP added: {new_ip}", "success")
            else:
                flash("IP already exists in trusted list.", "info")

        if new_device:
            patient_id = request.form.get("patient_id", "").strip()
            device_status = request.form.get("device_status", "").strip() or "Connected"
            last_reading = request.form.get("last_reading", "").strip() or "No reading available yet"

            if new_device not in TRUSTED_DEVICES:
                TRUSTED_DEVICES.append(new_device)

                IOT_DEVICES[new_device] = {
                    "device_id": f"D{len(IOT_DEVICES) + 1:03}",
                    "patient_id": patient_id,
                    "status": device_status,
                    "last_reading": last_reading
                }

                flash(f"Trusted device added: {new_device}", "success")
            else:
                flash("Device already exists in trusted list.", "info")

        return redirect(url_for("admin"))

    return render_template(
        "admin.html",
        trusted_ips=TRUSTED_IPS,
        trusted_devices=TRUSTED_DEVICES,
        users=USERS,
        patients=PATIENTS,
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=True)