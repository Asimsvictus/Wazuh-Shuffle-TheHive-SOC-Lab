# Shuffle Tools -> "Execute python" node: build_thehive_alert
# Turns a raw Wazuh alert (received by the Shuffle webhook as $exec) into a
# TheHive alert. The next node POSTs the printed JSON to /thehive/api/v1/alert.
import json

# Shuffle replaces $exec with the incoming Wazuh JSON before running this.
event = json.loads(r'''$exec''')
alert = event.get("all_fields", event)

rule = alert.get("rule", {})
agent = alert.get("agent", {})
data = alert.get("data", {})
win = data.get("win", {}).get("eventdata", {})

# Wazuh level 0-15  ->  TheHive severity 1-4
level = int(rule.get("level", 0))
if level >= 13:
    severity = 4
elif level >= 10:
    severity = 3
elif level >= 7:
    severity = 2
else:
    severity = 1

# Observables: only add fields that really exist in this alert
observables = [{"dataType": "hostname", "data": agent.get("name", "unknown"),
                "message": "Wazuh agent that raised the alert"}]
src_ip = win.get("ipAddress") or data.get("srcip")
if src_ip and src_ip not in ("-", "127.0.0.1", "::1"):
    observables.append({"dataType": "ip", "data": src_ip,
                        "message": "Source IP of the event", "ioc": True})
user = win.get("targetUserName")
if user and user != "-":
    observables.append({"dataType": "other", "data": user,
                        "message": "Targeted account"})

mitre = rule.get("mitre", {})
tags = ["wazuh", "rule:" + str(rule.get("id", "")), "agent:" + agent.get("name", "")]
tags += ["mitre:" + t for t in mitre.get("id", [])]

description = "\n".join([
    "**Wazuh alert forwarded by Shuffle**",
    "",
    "- Rule: " + str(rule.get("id")) + " - " + str(rule.get("description")),
    "- Level: " + str(level),
    "- Agent: " + str(agent.get("name")) + " (" + str(agent.get("ip", "n/a")) + ")",
    "- Time: " + str(alert.get("timestamp")),
    "- MITRE: " + (", ".join(mitre.get("technique", [])) or "n/a"),
    "",
    "Full log:",
    "",
    str(alert.get("full_log", ""))[:3000],
])

payload = {
    "type": "wazuh",
    "source": "Wazuh SIEM",
    "sourceRef": str(alert.get("id", "")),  # unique Wazuh alert ID = de-duplication key
    "title": "[Wazuh] " + str(rule.get("description", "Alert")),
    "description": description,
    "severity": severity,
    "tlp": 2,
    "pap": 2,
    "tags": tags,
    "observables": observables,
}
print(json.dumps(payload))
