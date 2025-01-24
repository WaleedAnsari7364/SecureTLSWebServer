import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

log_file = "server_logs.json"

def load_logs():
    try:
        with open(log_file, "r") as f:
            logs = json.load(f)
        return logs
    except FileNotFoundError:
        print("No logs found.")
        return []

def plot_logs(logs):
   
    logs_by_ip = defaultdict(list)
    for log in logs:
        logs_by_ip[log["ip"]].append(log)

   
    intrusion_counts = {ip: sum(1 for log in ip_logs if log["intrusion_detected"] == "Yes") for ip, ip_logs in logs_by_ip.items()}
    rate_limit_counts = {ip: sum(1 for log in ip_logs if log["rate_limited"] == "Yes") for ip, ip_logs in logs_by_ip.items()}

    
    intrusion_ips, intrusion_values = zip(*intrusion_counts.items()) if intrusion_counts else ([], [])
    rate_limit_ips, rate_limit_values = zip(*rate_limit_counts.items()) if rate_limit_counts else ([], [])

   
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))

    
    axes[0].bar(intrusion_ips, intrusion_values, color='r')
    axes[0].set_title("Intrusion Attempts by IP")
    axes[0].set_ylabel("Count")
    axes[0].set_xlabel("IP Address")
    axes[0].tick_params(axis='x', rotation=45)

    
    axes[1].bar(rate_limit_ips, rate_limit_values, color='b')
    axes[1].set_title("Rate Limit Violations by IP")
    axes[1].set_ylabel("Count")
    axes[1].set_xlabel("IP Address")
    axes[1].tick_params(axis='x', rotation=45)

    
    cities = [log["city"] for log in logs if log["city"] != "Unknown City"]
    city_counts = Counter(cities)
    axes[2].bar(city_counts.keys(), city_counts.values(), color='g')
    axes[2].set_title("Geographical Distribution of Clients (Cities)")
    axes[2].set_xlabel("City")
    axes[2].set_ylabel("Count")
    axes[2].tick_params(axis='x', rotation=45)

   
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    logs = load_logs()
    if logs:
        plot_logs(logs)
    else:
        print("No data to analyze.")
