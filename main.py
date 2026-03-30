from flask import Flask
import cs_ngsiem_query
import os

app = Flask(__name__)

@app.route("/", methods=["POST", "GET"])
def run_job():
    try:
        cs_ngsiem_query.main()
        return "OK", 200
    except Exception as e:
        print(f"[!] Job failed: {e}")
        return str(e), 500

@app.route("/env-check", methods=["GET"])
def env_check():
    all_env = {k: v for k, v in os.environ.items() if not k.startswith("PATH")}
    return all_env

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)