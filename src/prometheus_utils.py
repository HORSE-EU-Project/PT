import os
import time
import requests
from datetime import datetime
from zoneinfo import ZoneInfo

VALID_METRICS = {
    'container_network_receive_packets_total',
    'container_network_transmit_packets_total',
    'container_network_receive_bytes_total',
    'container_network_transmit_bytes_total'
}

PROMETHEUS_URL = "http://172.18.0.2:32047"

def query_prometheus(metric, pod, interface, namespace, start, end, step):
    url = 'http://172.18.0.2:32047/api/v1/query_range'
    params = {
        'query': f'{metric}{{pod="{pod}", interface="{interface}", namespace="{namespace}"}}',
        'start': start,
        'end': end,
        'step': step
    }
    response = requests.get(url, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Prometheus error {response.status_code}: {response.text}")

def parse_time(time_str: str, local_tz: str) -> datetime:
    local_dt = datetime.fromisoformat(time_str).replace(tzinfo=ZoneInfo(local_tz))
    return local_dt.astimezone(ZoneInfo("UTC"))

def is_valid_metric(metric_name: str) -> bool:
    return metric_name in VALID_METRICS
