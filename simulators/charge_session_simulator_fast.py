import paho.mqtt.client as mqtt
import time
import random
import argparse
import sys

# --- Configuration ---
# You can change these defaults or provide them as command-line arguments.
DEFAULT_MQTT_HOST = "localhost"
DEFAULT_MQTT_PORT = 1883
DEFAULT_OWNER_USERNAME = "changeme"
DEFAULT_VEHICLE_ID = "TESTCAR"
# Placeholder only. Pass the real one with --password (or via the environment) — a
# credential typed in here is a credential committed, and MQTT passwords for vehicles
# are the same secret the car itself authenticates with.
DEFAULT_VEHICLE_PASSWORD = "changeme"

# Simulation Parameters
SIMULATION_DURATION_MINUTES = 15  # How long the simulated charge will last
METRIC_UPDATE_INTERVAL_SECONDS = 2 # How often to send new metric values (FAST: 2 seconds instead of 30)
INITIAL_SOC = 45.0
FINAL_SOC = 80.0
INITIAL_KWH = 12.3
CHARGE_POWER_KW = 11.0
INITIAL_TEMP_C = 20.0


def publish_metric(client, topic_prefix, metric_name, value):
    """Helper function to publish a single metric."""
    topic = f"{topic_prefix}/metric/{metric_name.replace('.', '/')}"
    payload = str(value)
    result = client.publish(topic, payload)
    if result.rc == mqtt.MQTT_ERR_SUCCESS:
        print(f"  Published to {topic}: {payload}")
    else:
        print(f"  [ERROR] Failed to publish to {topic}: {mqtt.error_string(result.rc)}")
    return result

def run_simulation(args):
    """Connects to MQTT and runs the charge simulation."""

    client = mqtt.Client(client_id=f"ovms_sim_{args.user}")
    client.username_pw_set(args.user, args.password)

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"Successfully connected to MQTT broker at {args.host}:{args.port}")
        else:
            print(f"Failed to connect to MQTT, return code {rc}\nCheck broker, credentials, and MQTT user configuration in PyOVMS.")
            sys.exit(1)

    client.on_connect = on_connect

    try:
        client.connect(args.host, args.port, 60)
        client.loop_start()
    except Exception as e:
        print(f"Error connecting to MQTT broker: {e}")
        sys.exit(1)

    time.sleep(1) # Wait for connection to establish

    topic_prefix = f"ovms/{args.owner}/{args.user}"

    print("\n--- Starting FAST Charge Simulation ---")
    print(f"Vehicle: {args.user}, Owner: {args.owner}")
    print(f"Duration: {SIMULATION_DURATION_MINUTES} minutes, Update Interval: {METRIC_UPDATE_INTERVAL_SECONDS} seconds (FAST)")

    try:
        # 1. Start Charging
        print("\n[Step 1] Initiating charge session...")
        publish_metric(client, topic_prefix, "v.c.charging", "yes")
        time.sleep(2)

        # 2. Simulate the charge process
        print("\n[Step 2] Simulating charging progress...")

        num_steps = (SIMULATION_DURATION_MINUTES * 60) // METRIC_UPDATE_INTERVAL_SECONDS
        soc_increment = (FINAL_SOC - INITIAL_SOC) / num_steps
        kwh_increment = (CHARGE_POWER_KW * (METRIC_UPDATE_INTERVAL_SECONDS / 3600))

        current_soc = INITIAL_SOC
        current_kwh = INITIAL_KWH
        current_temp = INITIAL_TEMP_C

        for i in range(num_steps):
            print(f"\nUpdating metrics (Step {i+1}/{num_steps})...")

            # Update values
            current_soc += soc_increment
            current_kwh += kwh_increment
            current_power = CHARGE_POWER_KW * random.uniform(0.95, 1.05) # Add slight fluctuation
            current_temp += random.uniform(0.1, 0.3) # Temp slowly rises

            # Publish all metrics
            publish_metric(client, topic_prefix, "v.b.soc", f"{current_soc:.2f}")
            publish_metric(client, topic_prefix, "v.c.kwh", f"{current_kwh:.3f}")
            publish_metric(client, topic_prefix, "v.c.power", f"{current_power:.2f}")
            publish_metric(client, topic_prefix, "v.b.temp", f"{current_temp:.1f}")

            time.sleep(METRIC_UPDATE_INTERVAL_SECONDS)

        # 3. Stop Charging
        print("\n[Step 3] Stopping charge session...")
        # Send final metrics before stopping
        publish_metric(client, topic_prefix, "v.b.soc", f"{FINAL_SOC:.2f}")
        publish_metric(client, topic_prefix, "v.c.kwh", f"{current_kwh:.3f}")
        publish_metric(client, topic_prefix, "v.c.power", "0.0")
        time.sleep(1)
        # Send the final "no" to stop the session
        publish_metric(client, topic_prefix, "v.c.charging", "no")

        print("\n--- Simulation Complete ---")
        print("Check the PyOVMS web UI for the new charge session log.")

    except KeyboardInterrupt:
        print("\nSimulation interrupted by user. Sending 'charging: no'...")
        publish_metric(client, topic_prefix, "v.c.charging", "no")
    finally:
        client.loop_stop()
        client.disconnect()
        print("Disconnected from MQTT broker.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyOVMS Charge Session Simulator (FAST - 2 second updates)")
    parser.add_argument("--host", default=DEFAULT_MQTT_HOST, help=f"MQTT broker host (default: {DEFAULT_MQTT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_MQTT_PORT, help=f"MQTT broker port (default: {DEFAULT_MQTT_PORT})")
    parser.add_argument("--owner", default=DEFAULT_OWNER_USERNAME, help=f"The username of the vehicle's owner (for MQTT topic) (default: {DEFAULT_OWNER_USERNAME})")
    parser.add_argument("--user", default=DEFAULT_VEHICLE_ID, help=f"Vehicle ID, used as MQTT username (default: {DEFAULT_VEHICLE_ID})")
    parser.add_argument("--password", default=DEFAULT_VEHICLE_PASSWORD, help=f"Vehicle's server password, used as MQTT password (default: {DEFAULT_VEHICLE_PASSWORD})")

    args = parser.parse_args()

    run_simulation(args)
