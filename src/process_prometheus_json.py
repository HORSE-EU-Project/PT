from datetime import datetime, timezone

def process_prometheus_json(data):
    if data['status'] != 'success':
        raise ValueError("La consulta a Prometheus no fue exitosa.")

    results = data['data']['result']

    if not results:
        raise ValueError("No se encontraron datos en la respuesta de Prometheus.")

    # Seleccionar la primera métrica (en caso de que haya duplicadas)
    metric = results[0]
    pod = metric['metric'].get('pod', 'N/A')
    interface = metric['metric'].get('interface', 'N/A')
    values = metric['values']

    # Estructura para la salida de la función
    output = {
        "pod": pod,
        "interface": interface,
        "values": []
    }

    # Iterar sobre los valores para calcular los paquetes recibidos por intervalo (step)
    previous_value = None
    for timestamp, current_value in values:
        current_value = int(current_value)

        # Formateamos la marca de tiempo
        formatted_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')

        if previous_value is None:
            # El valor inicial de paquetes recibidos será 0
            packets_received = 0
        else:
            # Calculamos los paquetes recibidos en el intervalo
            packets_received = current_value - previous_value

        # Agregamos el resultado a la lista de valores
        output['values'].append([formatted_time, packets_received])

        # Por ultimo actualizamos el valor anterior
        previous_value = current_value

    return output

