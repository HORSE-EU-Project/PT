import threading
import requests
import datetime
import uuid
import xml.etree.ElementTree as ET
from flask import Response
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ORCHESTRATOR_URL = "http://localhost:8002/meservice"
METRICS_URL = "http://localhost:11025/query"

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
    if "block" in action_type:
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
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(seconds=duration)

    payload = {
        "pod": pod,
        "interface": interface,
        "metric": metric,
        "start": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
        "end": end_time.strftime("%Y-%m-%dT%H:%M:%S"),
        "step": f"{duration}s"
    }

    response = requests.post(METRICS_URL, json=payload)
    if response.status_code == 200:
        result = response.json()
        values = result.get("values", [])
        if values:
            last_value = values[-1][1]
            return float(last_value)
    return 0.0

def send_policy(xml_data):
    response = requests.post(ORCHESTRATOR_URL, data=xml_data,
                             headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[IBI] Sent XML to orchestrator: {response.status_code}")
    return response

def delete_policy(xml_data):
    requests.delete(ORCHESTRATOR_URL, data=xml_data,
                   headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[IBI] Deleted XML policy: {response.status_code}")

def process_ibi_json(data):
    xml_data = build_xml_from_json(data)
    if xml_data is None:
        return Response("Unrecognized action type", status=400)

    response = send_policy(xml_data)
    if response.status_code not in range(200, 300):
        return Response(response="Error sending policy to orchestrator", status=500)

    policy_duration = int(data.get("if-condition", {}).get("action", {}).get("duration", "60s").replace("s", ""))
    telemetry_duration = int(data.get("what-condition", {}).get("KPIs", {}).get("duration", "30s").replace("s", ""))

    threading.Timer(policy_duration, lambda: delete_policy(xml_data)).start()

    def collect_telemetry():
        kpi = data["what-condition"]["KPIs"]
        val = get_telemetry(kpi["element"]["node"], kpi["element"]["interface"], kpi["metric"], telemetry_duration)
        logger.info(f"Value after mitigation {val / telemetry_duration}")

    threading.Timer(telemetry_duration, collect_telemetry).start()
    return Response(response="✔ Policy applied and telemetry collection scheduled", status=200)