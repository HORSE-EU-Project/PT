from flask import Flask, request, jsonify
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)

def json_to_xml(json_data):
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

    configuration = ET.SubElement(itresource, "configuration", {"xsi:type": "RuleSetConfiguration"})

    capability = ET.SubElement(configuration, "capability")
    ET.SubElement(capability, "Name").text = json_data["type"].upper()

    configuration_rule = ET.SubElement(configuration, "configurationRule")
    
    configuration_rule_action = ET.SubElement(configuration_rule, "configurationRuleAction", {"xsi:type": "DNSACTION"})
    ET.SubElement(configuration_rule_action, "dnsActionType").text = "Rate"

    configuration_condition = ET.SubElement(configuration_rule, "configurationCondition", {"xsi:type": "DNSCondition"})
    ET.SubElement(configuration_condition, "isCNF").text = "false"

    dns_rate_parameters = ET.SubElement(configuration_condition, "dnsRateParameters")
    ET.SubElement(dns_rate_parameters, "operation").text = "RATE"
    ET.SubElement(dns_rate_parameters, "ip").text = json_data["Source"]
    
    ET.SubElement(dns_rate_parameters, "rate").text = "1"
    
    external_data = ET.SubElement(configuration_rule, "externalData", {"xsi:type": "Priority"})
    
    ET.SubElement(external_data, "value").text = "60000"

    ET.SubElement(configuration_rule, "Name").text = "Rule0"
    ET.SubElement(configuration_rule, "isCNF").text = "false"
    ET.SubElement(configuration, "Name").text = "Conf0"

    return ET.tostring(itresource_orchestration, encoding="utf-8", method="xml").decode()

@app.route('/')
def index():
    app.logger.info('Policy Translator is running')
    return 'Policy Translator is running', 200

@app.route('/generate/xml', methods=['POST'])
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
