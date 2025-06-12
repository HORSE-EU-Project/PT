import threading
import requests
from datetime import datetime,timezone,timedelta
import uuid
import xml.etree.ElementTree as ET
from flask import Response, jsonify
import os
import json
import logging
from prometheus_utils import (
    query_prometheus,
    is_valid_metric,
)
from process_prometheus_json import process_prometheus_json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ORCHESTRATOR_IP = os.getenv("ORCHESTRATOR_IP", "10.208.11.74")
ORCHESTRATOR_URL = f"http://{ORCHESTRATOR_IP}:8002/meservice"

def build_xml_from_json(data):
    orchestration_id = f"omspl_{uuid.uuid4().hex}"
    resource_id = f"mspl_{uuid.uuid4().hex}"

    root = ET.Element("ITResourceOrchestration",
                     id=orchestration_id,
                     xmlns="http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd",
                     attrib={"xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance"})

    itresource = ET.SubElement(root, "ITResource", id=resource_id, orchestrationID=orchestration_id)
    configuration = ET.SubElement(itresource, "configuration", {"xsi:type": "RuleSetConfiguration"})
    capability = ET.SubElement(configuration, "capability")

    rule = ET.SubElement(configuration, "configurationRule")
  
    action_type = data.get("if-condition", {}).get("action", {}).get("type", "").lower()
    if "monitor" in action_type:
        return "monitor"
    elif "block" in action_type:
        tipo = "filtering"
    elif "rate" in action_type:
        tipo = "qos"
    else:
        return None

    if tipo == "filtering":
        ET.SubElement(capability, "Name").text = "Filtering_L3"
        action = ET.SubElement(rule, "configurationRuleAction", {"xsi:type": "HorseFilteringAction"})
        ET.SubElement(action, "filteringActionType").text = "DROP"
        ET.SubElement(action, "id").text = data["id"]
        ET.SubElement(action, "description").text = "Hola, vamos a filtrar"

        condition = ET.SubElement(rule, "configurationCondition", {"xsi:type": "HorseFilteringCondition"})
        ET.SubElement(condition, "target").text = data["if-condition"]["action"]["value"]
        ET.SubElement(condition, "input_interface").text = "*"
        ET.SubElement(condition, "output_interface").text = data["if-condition"]["element"]["interface"]
        ET.SubElement(condition, "device").text = data["if-condition"]["element"]["node"]

        ET.SubElement(rule, "Name").text = f"Filtering_Rule_{data['id']}"
        ET.SubElement(configuration, "Name").text = f"Conf_{data['id']}"

    elif tipo == "qos":
        ET.SubElement(capability, "Name").text = "QoS"
        action = ET.SubElement(rule, "configurationRuleAction", {"xsi:type": "HorseQoSAction"})
        ET.SubElement(action, "qosActionType").text = "RATE"
        ET.SubElement(action, "id").text = data["id"]
        ET.SubElement(action, "description").text = "Hola, vamos a hacer QoS"

        condition = ET.SubElement(rule, "configurationCondition", {"xsi:type": "HorseQoSCondition"})
        ET.SubElement(condition, "device").text = data["if-condition"]["element"]["node"]
        ET.SubElement(condition, "interface").text = data["if-condition"]["element"]["interface"]
        ET.SubElement(condition, "throughput").text = data["if-condition"]["action"]["value"]
        ET.SubElement(condition, "unit").text = data["if-condition"]["action"].get("unit", "mbps")
        ET.SubElement(condition, "mode").text = data["if-condition"]["action"].get("mode", "full")

        ET.SubElement(rule, "Name").text = f"QoS_Rule_{data['id']}"
        ET.SubElement(configuration, "Name").text = f"Conf_{data['id']}"

    ET.SubElement(itresource, "priority").text = "1000"
    enablers = ET.SubElement(itresource, "enablerCandidates")
    ET.SubElement(enablers, "enabler").text = "ceos"

    return ET.tostring(root, encoding="utf-8", method="xml").decode()

def get_telemetry(pod, interface, metric, duration):
    # Traduce los nombres de las métricas para la consulta de Prometheus
    prometheus_metric = metric
    is_rate = False
    
    if metric in ["packets", "packets-per-second"]:
        prometheus_metric = "container_network_transmit_packets_total"
        is_rate = "per-second" in metric
    elif metric in ["bytes", "bytes-per-second"]:
        prometheus_metric = "container_network_transmit_bytes_total"
        is_rate = "per-second" in metric

    if not is_valid_metric(prometheus_metric):
        return jsonify({"error": "Invalid metric"}), 400
    
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(seconds=duration)
    
    # Añade la zona horaria UTC y formatea como ISO 8601
    start_iso = start_time.replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    end_iso = end_time.replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
    
    namespace = "horse-complete"  # Namespace por defecto

    try:
        json_data = query_prometheus(prometheus_metric, pod, interface, namespace, start_iso, end_iso, duration)
        if json_data:
            json_processed = process_prometheus_json(json_data)
            
            # Suma todos los valores de la métrica
            total_value = 0
            if "values" in json_processed:
                for timestamp_value_pair in json_processed["values"]:
                    if len(timestamp_value_pair) >= 2:
                        try:
                            total_value += float(timestamp_value_pair[1])
                        except (ValueError, TypeError):
                            pass
            # Devuelve el valor total y si es una tasa
            return total_value, is_rate
        else:
            raise ValueError("No data received from Prometheus.")
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

def send_policy(xml_data):
    response = requests.post(ORCHESTRATOR_URL, data=xml_data,
                             headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[IBI] Sent XML to orchestrator: {response.status_code}")
    return response

def delete_policy(xml_data):
    response = requests.delete(ORCHESTRATOR_URL, data=xml_data,
                   headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[IBI] Deleted XML policy: {response.status_code}")

def collect_telemetry(data, telemetry_duration):
    kpi = data["what-condition"]["KPIs"]
    metric = kpi.get("metric", "unknown")
    node = kpi["element"]["node"]
    interface = kpi["element"]["interface"]
    device = f"{node}-{interface}"

    result = get_telemetry(node, interface, metric, telemetry_duration)
    
    # Check if we got an error response
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], Response):
        logger.error(f"Failed to collect telemetry: {result[0].get_data(as_text=True)}")
        return
    
    val, is_rate = result
    
    res = {
            "device" : device,
            "metric" : metric,
            "value" : val / telemetry_duration if is_rate else val,
            "duration" : f"{telemetry_duration}s"
    }

    logger.info(f"Metrics obtained:\n{json.dumps(res, indent=4)}")

def process_ibi_json(data):
    policy_duration = int(data.get("if-condition", {}).get("action", {}).get("duration", "60s").replace("s", ""))
    telemetry_duration = int(data.get("what-condition", {}).get("KPIs", {}).get("duration", "30s").replace("s", ""))

    action = data['if-condition']['action']
    element = data['if-condition']['element']
    xml_data = build_xml_from_json(data)
    xml_data2 = build_xml_from_json(data)

    if xml_data == "monitor":
        threading.Timer(policy_duration, lambda: collect_telemetry(data, telemetry_duration)).start()
        logger.info(f"Telemetry scheduled in {policy_duration}s with a duration of {telemetry_duration}s")
        return Response("✔ Monitor task scheduled", status=200)

    if xml_data is None:
        return Response("Unrecognized action type", status=400)

    response = send_policy(xml_data)
    if response.status_code not in range(200, 300):
        return Response(response="Error sending policy to orchestrator", status=500)

    threading.Timer(policy_duration, lambda: delete_policy(xml_data2)).start()

    threading.Timer(policy_duration, lambda: collect_telemetry(data, telemetry_duration)).start()
    logger.info(f"Received '{action['type']}' policy in pod {element['node']} with a duration of {action['duration']}")
    logger.info(f"Policy applied and telemetry scheduled in {policy_duration}s with a duration of {telemetry_duration}s")
    return Response(response="✔ Policy applied and telemetry collection scheduled", status=200)
