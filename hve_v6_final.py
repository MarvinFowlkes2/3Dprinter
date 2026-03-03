import shodan
import requests
import time

SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)

def run_test(query_name, search_query):
    print(f"\n[*] TESTING: {query_name} ({search_query})")
    verified = 0
    honeypots = 0
    total = 0
    latencies = []
    
    try:
        for page in range(1, 3):
            results = api.search(search_query, page=page)
            for result in results['matches']:
                total += 1
                ip = result['ip_str']
                
                start_time = time.time()
                try:
                    # Tier 1 Probe
                    r = requests.get(f"http://{ip}/api/version", timeout=2.0)
                    end_time = time.time()
                    
                    if r.status_code == 200:
                        verified += 1
                        latencies.append(end_time - start_time)
                    else:
                        # Logic: It responded, but it's not the 3D printer API we want
                        if query_name == "Honeypot Hunt":
                            honeypots += 1
                except Exception:
                    # Logic: Connection Refused or Timeout (The "Silent Decoy" behavior)
                    if query_name == "Honeypot Hunt":
                        honeypots += 1
            print(f"    - Finished Page {page}")
    except Exception as e:
        print(f"    - Error: {e}")
        
    avg_latency = (sum(latencies) / len(latencies)) if latencies else 0
    return total, honeypots, verified, avg_latency

# --- Experimental Execution ---
t_o, h_o, v_o, l_o = run_test("Printer Hunt", "OctoPrint")
t_t, h_t, v_t, l_t = run_test("Honeypot Hunt", 'title:"Honeywell"')

print(f"\n" + "="*50)
print("   FOWLKES DEFENDER: THREAT INTELLIGENCE REPORT")
print("="*50)
print(f"OCTOPRINT (PRINTERS): {v_o} Verified | Avg Response: {l_o:.3f}s")
print(f"HONEYWELL (DECEPTION): {h_t} Decoys   | Avg Response: {l_t:.3f}s")
print("-" * 50)

if t_t > 0:
    deception_index = (h_t / t_t) * 100
    print(f"DECEPTION INDEX: {deception_index:.1f}%")
else:
    print("DECEPTION INDEX: N/A")

print("="*50)
