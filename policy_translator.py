from flask import Flask, request, jsonify, Response
import xml.etree.ElementTree as ET
import requests
import json
import time

app = Flask(__name__)

def json_to_xml(json_data):
    try:
        itresource_orchestration = ET.Element("ITResourceOrchestration", 
                                              xmlns="http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd",
                                              attrib={
                                                  'xmlns:xsi': "http://www.w3.org/2001/XMLSchema-instance",
                                                  'id': "omspl_5b0fd7359a5e40fe92399710c1152ed9",
                                                  'xsi:schemaLocation': "http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd mspl.xsd"
                                              })

        itresource = ET.SubElement(itresource_orchestration, "ITResource", 
                                   id="mspl_9e9dbbdfad5d4ef588fc5ec579f83c59", 
                                   orchestrationID="omspl_5b0fd7359a5e40fe92399710c1152ed9")

        # Configuration element
        configuration = ET.SubElement(itresource, "configuration", {"xsi:type": "RuleSetConfiguration"})

        # Capability element
        capability = ET.SubElement(configuration, "capability")
        ET.SubElement(capability, "Name").text = "DNS" 

        # ConfigurationRule element
        configuration_rule = ET.SubElement(configuration, "configurationRule")

        configuration_rule_action = ET.SubElement(configuration_rule, "configurationRuleAction", {"xsi:type": "DNSACTION"})
        ET.SubElement(configuration_rule_action, "dnsActionType").text = "Rate"

        configuration_condition = ET.SubElement(configuration_rule, "configurationCondition", {"xsi:type": "DNSCondition"})
        ET.SubElement(configuration_condition, "isCNF").text = "false"

        dns_rate_parameters = ET.SubElement(configuration_condition, "dnsRateParameters")
        ET.SubElement(dns_rate_parameters, "operation").text = "RATE" # json_data["if"]["action"]["type"].upper() == RATE LIMIT
        
        element_interface = json_data["if"]["element"]["interface"]
        if element_interface == "*":
            ET.SubElement(dns_rate_parameters, "ip").text = "0.0.0.0"
        else:
            ET.SubElement(dns_rate_parameters, "ip").text = element_interface

        ET.SubElement(dns_rate_parameters, "rate").text = json_data["if"]["action"]["value"]

        external_data = ET.SubElement(configuration_rule, "externalData", {"xsi:type": "Priority"})
        ET.SubElement(external_data, "value").text = "60000"

        ET.SubElement(configuration_rule, "Name").text = "Rule0"
        ET.SubElement(configuration_rule, "isCNF").text = "false"

        # # Name element in Configuration
        ET.SubElement(configuration, "Name").text = "Conf0"

        # EnforcementRequirements element
        enforcement_requirements = ET.SubElement(itresource, "enforcementRequirements")
        conf_type = ET.SubElement(enforcement_requirements, "confType")
        conf_only = ET.SubElement(conf_type, "confOnly")
        conf_only.text = "true"
        instance_id = ET.SubElement(conf_type, "instanceID")
        instance_id.text = "dns-s1"

        return ET.tostring(itresource_orchestration, encoding="utf-8", method="xml").decode()
    except KeyError as e:
        print(f"KeyError in json_to_xml: {str(e)}")
        raise

def create_output_template(input_value, interface_value):
    output_template = {
        "id": "1235",
        "topology_name": "horse_ddos",
        "attack": "DDoS",
        "what": {
            "KPIs": {
                "element": {
                    "node": "dns-s",
                    "interface": interface_value
                },
                "metric": "avg-time-requests",
                "result": {
                    # "value": input_value,
                    "initial-value": "0.532",
                    "current-value": "0.022",
                    "unit": "seconds"
                }
            }
        }
    }
    return output_template

@app.route('/')
def index():
    app.logger.info('Policy Translator is running')
    return 'Policy Translator is running', 200

@app.route('/api', methods=['POST'])
def api():
    json_data = request.get_json()
    if not json_data:
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        xml_data = json_to_xml(json_data)
    except KeyError as e:
        return jsonify({"error": f"Missing key: {str(e)}"}), 400

    try: 
        ET.fromstring(xml_data)  # Validar XML
    except Exception as e:
        return jsonify({"error": f"Validating MSPL translation: {str(e)}"}), 400
    
    return Response(xml_data, mimetype='application/xml')

@app.route('/send_policy', methods=['POST'])
def send_policy():
    try:
        json_data = request.get_json()
        if not json_data:
            return jsonify({"error": "Invalid JSON"}), 400
        
        try:
            xml_data = json_to_xml(json_data)
        except KeyError as e:
            return jsonify({"error": f"Missing key: {str(e)}"}), 400

        response = requests.post('http://155.54.95.84:8002/meservice', data=xml_data, headers={'Content-Type': 'application/xml', 'Cache-Control': 'no-cache'})

        if 200 <= response.status_code < 300:
            try:
                input_value = json_data["if"]["action"]["value"]
                interface_value = json_data["if"]["element"]["interface"]
                output_json = create_output_template(input_value, interface_value)
                # return Response(response=json.dumps(output_json), status=200, mimetype='application/json')
                time.sleep(10)
                json_received = json.dumps(json_data, indent=2, sort_keys=False)
                return Response(response=json_received, status=200, mimetype='application/json')
            except KeyError as e:
                print(f"Error extracting key from JSON: {str(e)}")
                return jsonify({"error": f"Missing key in input JSON: {str(e)}"}), 400
        else:
            print(f"Orchestrator response status code: {response.status_code}")
            return Response(response=json.dumps({"error": "Failed to send XML to orchestrator"}), status=500, mimetype='application/json')
    
    except Exception as e:
        print(f"Error decoding JSON: {str(e)}")
        return jsonify({"error": f"Failed to decode JSON object: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
