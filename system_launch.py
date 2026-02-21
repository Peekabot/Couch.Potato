import psutil
import time
import gspread
import socket
import numpy as np
from datetime import datetime
from oauth2client.service_account import ServiceAccountCredentials

# --- CONFIGURATION ---
SHEET_NAME = 'Server_MCMC_Logs'
CREDENTIALS_FILE = 'service_account.json'
SAMPLE_INTERVAL = 30  # seconds

# --- MCMC STATE MAPPING ---
def get_state(cpu, mem):
    """Maps CPU and Memory percentages to MCMC states."""
    load = max(cpu, mem)
    if load < 20: return 'IDLE'
    if load < 60: return 'NORMAL'
    if load < 85: return 'HIGH'
    return 'CRITICAL'

# --- STEADY-STATE CALCULATION ---
def compute_steady_state(transitions):
    """Computes steady-state probabilities from a transition matrix."""
    states = ['IDLE', 'NORMAL', 'HIGH', 'CRITICAL']
    n = len(states)
    matrix = np.zeros((n, n))

    for i, s1 in enumerate(states):
        total = sum(transitions[s1].values())
        if total > 0:
            for j, s2 in enumerate(states):
                matrix[i, j] = transitions[s1][s2] / total
        else:
            matrix[i, i] = 1.0

    try:
        vals, vecs = np.linalg.eig(matrix.T)
        pi = vecs[:, np.isclose(vals, 1)].real
        pi = pi / pi.sum()
        return pi.flatten()
    except:
        return [0.25] * 4

# --- INITIALIZATION ---
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name(CREDENTIALS_FILE, scope)
client = gspread.authorize(creds)
sheet = client.open(SHEET_NAME).sheet1

hostname = socket.gethostname()
transition_counts = {s: {s2: 1 for s2 in ['IDLE', 'NORMAL', 'HIGH', 'CRITICAL']}
                     for s in ['IDLE', 'NORMAL', 'HIGH', 'CRITICAL']}
last_state = None

print(f"Monitoring started for {hostname}...")

# --- MAIN LOOP ---
while True:
    try:
        cpu_pct = psutil.cpu_percent(interval=1)
        mem_pct = psutil.virtual_memory().percent
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        current_state = get_state(cpu_pct, mem_pct)

        if last_state:
            transition_counts[last_state][current_state] += 1

        probs = compute_steady_state(transition_counts)
        predicted_next = ['IDLE', 'NORMAL', 'HIGH', 'CRITICAL'][np.argmax(probs)]

        row = [
            timestamp, cpu_pct, mem_pct, current_state, predicted_next,
            float(probs[0]), float(probs[1]), float(probs[2]), float(probs[3]),
            hostname
        ]
        sheet.append_row(row)

        last_state = current_state
        time.sleep(SAMPLE_INTERVAL - 1)

    except Exception as e:
        print(f"Error: {e}")
        time.sleep(10)
