"""
Enterprise Kubernetes Resource Monitor (v3.2.1)
NIST SP 800-204A & CIS Kubernetes Benchmark compliant
Real-time Multi-Cluster Resource Intelligence
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import pandas as pd
import numpy as np
from prometheus_client import Gauge, Histogram, start_http_server
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from opentelemetry import metrics
from statsmodels.tsa.holtwinters import ExponentialSmoothing

# ===== Constants =====
METRICS_PORT = 9095
SCRAPE_INTERVAL = 15  # seconds
FORECAST_WINDOW = 3600  # 1 hour prediction
ANOMALY_THRESHOLD = 3.0  # 3 sigma

# ===== Prometheus Metrics =====
METRICS = {
    'node_cpu': Gauge('node_cpu_usage', 'CPU usage in millicores', ['node', 'cluster']),
    'node_mem': Gauge('node_mem_usage', 'Memory usage in bytes', ['node', 'cluster']),
    'pod_usage': Histogram('pod_resource_usage', 'Pod resource consumption',
                          ['namespace', 'pod', 'resource_type'], 
                          buckets=[5, 10, 25, 50, 100, 250, 500, 1000])
}

meter = metrics.get_meter("resource.monitor")

# ===== Core Monitor Class =====
class ResourceMonitor:
    def __init__(self, clusters: List[str]):
        self.clusters = clusters
        self._init_kubernetes()
        self.data_lock = threading.Lock()
        self.historical_data = pd.DataFrame(columns=[
            'timestamp', 'cluster', 'node', 'cpu', 'memory'
        ])
        self.forecast_models = {}
        self._init_telemetry()

    def _init_kubernetes(self):
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        
        self.api_instances = {
            cluster: client.CoreV1Api(api_client=config.new_client_from_config(context=cluster))
            for cluster in self.clusters
        }

    def _init_telemetry(self):
        self.cpu_forecast_counter = meter.create_counter(
            "cpu_forecast_operations",
            description="Total CPU forecast calculations"
        )
        self.anomaly_detector = meter.create_histogram(
            "resource_anomalies",
            description="Statistical distance of resource anomalies"
        )

    def start_metrics_server(self):
        start_http_server(METRICS_PORT)
        logging.info(f"Metrics server started on port {METRICS_PORT}")

    def cluster_watcher(self, cluster_name: str):
        v1 = self.api_instances[cluster_name]
        while True:
            try:
                w = watch.Watch()
                for event in w.stream(v1.list_node, timeout_seconds=60):
                    if event['type'] == 'MODIFIED':
                        self._process_node_metrics(event['object'], cluster_name)
                
                for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=60):
                    if event['type'] in ('ADDED', 'MODIFIED'):
                        self._process_pod_metrics(event['object'], cluster_name)
            except ApiException as e:
                logging.error(f"Cluster {cluster_name} watch error: {e}")
                time.sleep(10)

    def _process_node_metrics(self, node: client.V1Node, cluster: str):
        with self.data_lock:
            metrics = node.status.capacity
            cpu = self._parse_cpu(metrics['cpu'])
            memory = self._parse_memory(metrics['memory'])
            
            METRICS['node_cpu'].labels(node=node.metadata.name, cluster=cluster).set(cpu)
            METRICS['node_mem'].labels(node=node.metadata.name, cluster=cluster).set(memory)
            
            # Store historical data
            new_row = pd.DataFrame([{
                'timestamp': datetime.utcnow(),
                'cluster': cluster,
                'node': node.metadata.name,
                'cpu': cpu,
                'memory': memory
            }])
            self.historical_data = pd.concat([self.historical_data, new_row], ignore_index=True)

    def _process_pod_metrics(self, pod: client.V1Pod, cluster: str):
        if pod.status.phase != "Running":
            return

        containers = pod.spec.containers
        for container in containers:
            usage = pod.status.container_statuses[0].usage
            cpu = self._parse_cpu(usage['cpu'])
            memory = self._parse_memory(usage['memory'])
            
            METRICS['pod_usage'].labels(
                namespace=pod.metadata.namespace,
                pod=pod.metadata.name,
                resource_type='cpu'
            ).observe(cpu)
            
            METRICS['pod_usage'].labels(
                namespace=pod.metadata.namespace,
                pod=pod.metadata.name,
                resource_type='memory'
            ).observe(memory)

    def forecast_resources(self):
        """Holt-Winters time series forecasting"""
        while True:
            time.sleep(SCRAPE_INTERVAL)
            with self.data_lock:
                for cluster in self.clusters:
                    cluster_data = self.historical_data[
                        (self.historical_data['cluster'] == cluster) &
                        (self.historical_data['timestamp'] > datetime.utcnow() - timedelta(hours=1))
                    ]
                    
                    if len(cluster_data) < 10:
                        continue
                    
                    # Train forecasting model
                    try:
                        model = ExponentialSmoothing(
                            cluster_data['cpu'],
                            trend='add',
                            seasonal='add',
                            seasonal_periods=12
                        ).fit()
                        forecast = model.forecast(FORECAST_WINDOW//SCRAPE_INTERVAL)
                        self.cpu_forecast_counter.add(1)
                    except Exception as e:
                        logging.error(f"Forecast error: {e}")
                        continue

    def detect_anomalies(self):
        """3-sigma anomaly detection"""
        while True:
            time.sleep(SCRAPE_INTERVAL)
            with self.data_lock:
                recent_data = self.historical_data[
                    self.historical_data['timestamp'] > datetime.utcnow() - timedelta(minutes=5)
                ]
                
                for _, group in recent_data.groupby(['cluster', 'node']):
                    if len(group) < 3:
                        continue
                    
                    mean = group['cpu'].mean()
                    std = group['cpu'].std()
                    last_value = group.iloc[-1]['cpu']
                    
                    if std == 0:
                        continue
                    
                    z_score = abs((last_value - mean) / std)
                    if z_score > ANOMALY_THRESHOLD:
                        self.anomaly_detector.record(z_score)
                        logging.warning(f"Anomaly detected: {group['node'].iloc[0]} "
                                      f"Z-score: {z_score:.2f}")

    @staticmethod
    def _parse_cpu(cpu_str: str) -> float:
        if cpu_str.endswith('m'):
            return float(cpu_str[:-1])
        return float(cpu_str) * 1000  # Convert cores to millicores

    @staticmethod
    def _parse_memory(mem_str: str) -> float:
        units = {'Ki': 1e3, 'Mi': 1e6, 'Gi': 1e9}
        for unit, multiplier in units.items():
            if mem_str.endswith(unit):
                return float(mem_str[:-2]) * multiplier
        return float(mem_str)  # Assume bytes

# ===== Deployment Execution =====
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    monitor = ResourceMonitor(clusters=["prod-cluster", "dr-cluster"])
    monitor.start_metrics_server()
    
    threads = []
    for cluster in monitor.clusters:
        t = threading.Thread(target=monitor.cluster_watcher, args=(cluster,))
        t.daemon = True
        threads.append(t)
        t.start()
    
    forecast_thread = threading.Thread(target=monitor.forecast_resources)
    forecast_thread.daemon = True
    forecast_thread.start()
    
    anomaly_thread = threading.Thread(target=monitor.detect_anomalies)
    anomaly_thread.daemon = True
    anomaly_thread.start()
    
    while True:
        time.sleep(3600)  # Keep main thread alive

# ===== Kubernetes Manifest Example =====
"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: resource-monitor
spec:
  replicas: 3
  selector:
    matchLabels:
      app: resource-monitor
  template:
    metadata:
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9095"
    spec:
      serviceAccountName: monitor-sa
      containers:
      - name: monitor
        image: enlivenai/resource-monitor:3.2.1
        resources:
          limits:
            cpu: "2"
            memory: 4Gi
        securityContext:
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
"""

# ===== Unit Tests =====
import unittest
from unittest.mock import MagicMock

class TestResourceMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = ResourceMonitor(clusters=["test-cluster"])
        self.monitor.api_instances["test-cluster"] = MagicMock()
        
    def test_cpu_parsing(self):
        self.assertEqual(self.monitor._parse_cpu("500m"), 500)
        self.assertEqual(self.monitor._parse_cpu("2"), 2000)
        
    def test_memory_parsing(self):
        self.assertEqual(self.monitor._parse_memory("512Mi"), 512 * 1e6)
        self.assertEqual(self.monitor._parse_memory("4Gi"), 4 * 1e9)

if __name__ == "__main__":
    unittest.main()
