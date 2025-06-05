import threading
import requests
from flask import Response
import xml.etree.ElementTree as ET
import uuid
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ORCHESTRATOR_URL = os.environ.get("ORCHESTRATOR_URL", "http://10.208.99.74:8002/meservice")

def extract_attack_info(xml_string):
    try:
        root = ET.fromstring(xml_string)

        attack = root.find('.//CyberAttack/Type')
        attacker = root.find('.//ThreatActor/Source')
        victim = root.find('.//AttackLocation')
        duration_elem = root.find('.//Parameter/Duration')
        protocol_elem = root.find('.//Parameter/Protocol')
        flag_elem = root.find('.//Parameter/Flag')

        return {
            "attack": attack.text.strip() if attack is not None else "Unknown",
            "attacker": attacker.text.strip() if attacker is not None else "internet",
            "victim": victim.text.strip() if victim is not None else "dns-c1",
            "duration": int(duration_elem.text.strip()) if duration_elem is not None else 30,
            "protocol": protocol_elem.text.strip() if protocol_elem is not None else None,
            "flag": flag_elem.text.strip() if flag_elem is not None else None
        }
    except Exception as e:
        logger.error(f"[ERROR] extracting attack info: {e}")
        return None

def build_attack_xml(info):
    nsmap = {
        "xmlns": "http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance"
    }
    orchestration_id = f"omspl_{uuid.uuid4().hex}"
    resource_id = f"mspl_{uuid.uuid4().hex}"

    root = ET.Element("ITResourceOrchestration", id=orchestration_id, **nsmap)
    itresource = ET.SubElement(root, "ITResource", id=resource_id, orchestrationID=orchestration_id)

    configuration = ET.SubElement(itresource, "configuration", {"xsi:type": "RuleSetConfiguration"})
    capability = ET.SubElement(configuration, "capability")
    ET.SubElement(capability, "Name").text = "sim_attack"

    rule = ET.SubElement(configuration, "configurationRule")
    action = ET.SubElement(rule, "configurationRuleAction", {"xsi:type": "HorseAttackAction"})
    ET.SubElement(action, "id").text = "0007"
    ET.SubElement(action, "attack").text = info["attack"]

    attackParams = ET.SubElement(action, "attackParams")
    if info["protocol"]:
        ET.SubElement(attackParams, "protocol").text = info["protocol"]
    if info["flag"]:
        ET.SubElement(attackParams, "flag").text = info["flag"]

    ET.SubElement(action, "description").text = "Hola, vamos a filtrar"
    ET.SubElement(action, "duration").text = f"{info['duration']}s"

    condition = ET.SubElement(rule, "configurationCondition", {"xsi:type": "HorseAttackCondition"})
    ET.SubElement(condition, "attacker").text = info["attacker"]
    ET.SubElement(condition, "victim").text = info["victim"]

    ET.SubElement(rule, "Name").text = "Attack_Rule_0010"
    ET.SubElement(configuration, "Name").text = "Conf_0010"

    ET.SubElement(itresource, "priority").text = "1000"
    enablers = ET.SubElement(itresource, "enablerCandidates")
    ET.SubElement(enablers, "enabler").text = "kne_pod"

    return ET.tostring(root, encoding="utf-8", method="xml").decode()

def send_policy(xml_data):
    response = requests.post(ORCHESTRATOR_URL, data=xml_data,
                             headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[EM] Sent XML to orchestrator: {response.status_code}")
    return response

def delete_policy(xml_data):
    response = requests.delete(ORCHESTRATOR_URL, data=xml_data,
                               headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[EM] Deleted XML policy: {response.status_code}")

def process_em_xml(xml_data):
    info = extract_attack_info(xml_data)
    if not info:
        return Response(response="Invalid EM XML format", status=400)

    attack_xml = build_attack_xml(info)
    send_response = send_policy(attack_xml)
    if send_response.status_code not in range(200, 300):
        return Response(response="Error sending XML", status=500)

    threading.Timer(info["duration"], lambda: delete_policy(attack_xml)).start()
    return Response(response="✔ Policy received and scheduled for deletion", status=200)