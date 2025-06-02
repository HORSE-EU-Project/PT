from flask import Flask, request, Response
import threading
import time
import em_handler
import ibi_handler

app = Flask(__name__)

@app.route('/from_em', methods=['POST'])
def handle_em():
    xml_data = request.data.decode("utf-8")
    return em_handler.process_em_xml(xml_data)

@app.route('/from_ibi', methods=['POST'])
def handle_ibi():
    json_data = request.get_json()
    return ibi_handler.process_ibi_json(json_data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)