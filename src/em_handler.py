import threading
import requests
from flask import Response
import xml.etree.ElementTree as ET
import uuid
import os
import logging
from policy_file_cache import PolicyFileCache

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
policy_cache = PolicyFileCache()

ORCHESTRATOR_IP = os.getenv("ORCHESTRATOR_IP", "10.208.11.74")
ORCHESTRATOR_URL = f"http://{ORCHESTRATOR_IP}:8002/meservice"

def extract_attack_info(xml_string):
    try:
        root = ET.fromstring(xml_string)

        attack = root.find('.//CyberAttack/Type')
        attacker = root.find('.//ThreatActor/Source')
        victim = root.find('.//AttackLocation')
        duration_elem = root.find('.//Parameter/Duration')

        attack_info = {
            "attack": attack.text.strip() if attack is not None else "Unknown",
            "attacker": attacker.text.strip() if attacker is not None else "internet",
            "victim": victim.text.strip() if victim is not None else "dns-c1",
            "duration": int(duration_elem.text.strip()) if duration_elem is not None else 30,
        }

        attack_text = attack.text.strip()

        if attack_text == 'DDoS_Downlink':
            protocol_elem = root.find('.//Parameter/Protocol')
            flag_elem = root.find('.//Parameter/Flag')
            attack_info["protocol"] = protocol_elem.text.strip() if protocol_elem is not None else "TCP"
            attack_info["flag"] = flag_elem.text.strip() if flag_elem is not None else "SYN"
        elif attack_text == 'DNS_Amplification':
            port_elem = root.find('.//Parameter/Port')
            protocol_elem = root.find('.//Parameter/Protocol')
            domain_elem = root.find('.//Parameter/DomainName')
            attack_info["protocol"] = protocol_elem.text.strip() if protocol_elem is not None else "UDP"
            attack_info["port"] = port_elem.text.strip() if port_elem is not None else "53"
            attack_info["domain_name"] = domain_elem.text.strip() if domain_elem is not None else "dominio1.org"

        return attack_info
    
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
    if 'protocol' in info:
        ET.SubElement(attackParams, "protocol").text = info["protocol"]
    if 'flag' in info:
        ET.SubElement(attackParams, "flag").text = info["flag"]
    if 'port' in info:
        ET.SubElement(attackParams, "port").text = info["port"]
    if 'domain_name' in info:
        ET.SubElement(attackParams, "domain_name").text = info["domain_name"]

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

# (Not used anymore)
def send_policy(xml_data):
    response = requests.post(ORCHESTRATOR_URL, data=xml_data,
                             headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})
    logger.info(f"[EM] Sent XML to orchestrator: {response.status_code}")
    return response

def process_em_xml(xml_data):
    info = extract_attack_info(xml_data)
    if not info:
        return Response(response="Invalid EM XML format", status=400)

    attack_xml = build_attack_xml(info)

    attack_type = info["attack"]  # ej: "DDoS_Downlink"
    success = policy_cache.store_policy(attack_type, attack_xml)
    
    if success:
        return Response(response="✔ Policy stored", status=200)
    else:
        return Response(response="Error storing policy", status=500)
