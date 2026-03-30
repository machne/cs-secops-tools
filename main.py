from flask import Flask
import cs_ngsiem_query

app = Flask(__name__)

@app.route("/", methods=["POST", "GET"])
def run_job():
    try:
        cs_ngsiem_query.main()
        return "OK", 200
    except Exception as e:
        print(f"[!] Job failed: {e}")
        return str(e), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)