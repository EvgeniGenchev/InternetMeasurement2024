import scapy.all as scapy
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import time
from tqdm import tqdm

def read_domains(file_path):
    with open(file_path, 'r') as file:
        domains = [line.strip() for line in file]
    return domains

def resolve_domain(domain):
    dns_req = scapy.IP(dst="8.8.8.8")/scapy.UDP(dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain))
    dns_resp = scapy.sr1(dns_req, verbose=0, timeout=2)
    return dns_resp

def parse_dns_response(response):
    if response and response.haslayer(scapy.DNSRR):
        answer = response[scapy.DNS].an
        if answer:
            return {
                'name': answer.rrname.decode('utf-8'),
                'type': answer.type,
                'rdata': answer.rdata.decode('utf-8') if isinstance(answer.rdata, bytes) else str(answer.rdata),
                'ttl': answer.ttl,
            }
    return None

def save_to_parquet(data, file_path):
    df = pd.DataFrame(data)
    table = pa.Table.from_pandas(df)
    pq.write_table(table, file_path)

def main(input_file, output_file):
    domains = read_domains(input_file)
    results = []
    
    for domain in tqdm(domains, desc="Resolving domains"):
        response = resolve_domain(domain)
        parsed_response = parse_dns_response(response)
        if parsed_response:
            results.append(parsed_response)
        time.sleep(0.1)

    save_to_parquet(results, output_file)
    print(f'Data saved to {output_file}')

if __name__ == "__main__":
    input_file = './privacy_domains.txt'
    output_file = 'dns_responses_priv.parquet'
    main(input_file, output_file)

