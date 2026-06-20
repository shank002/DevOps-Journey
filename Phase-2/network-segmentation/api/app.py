from flask import Flask, jsonify
import psycopg2, os

app = Flask(__name__)

@app.route('/data')
def get_data():
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    cur = conn.cursor()
    cur.execute("SELECT now();")
    result = cur.fetchone()
    return jsonify({"time": str(result[0])})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)

