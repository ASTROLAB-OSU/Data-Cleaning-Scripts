import os
import re
import csv
from collections import defaultdict

total_follow_threshhold = 10000
follow_percent_threshhold = 50
chain_length_threshhold = 3
src = "[Insert Config]"
dst = "../results/suspicious_email_groups"

def extract_domain(email):
    """Extract domain from email address"""
    try:
        return email.strip().split('@')[1].lower()
    except (IndexError, AttributeError):
        return None

def find_groups(src_file, dst_file):
    # Track what domain follows each domain
    domain_sequences = defaultdict(lambda: defaultdict(int))
    # Track previous domain and password in each file
    prev_domain = None
    prev_password = None
    
    # Use os.walk to traverse all directories and files
    for dirpath, _, filenames in os.walk(src_file):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            prev_domain = None  # Reset for each file
            prev_password = None
            
            try:
                with open(file_path, 'r', encoding="latin-1") as f:
                    print(f"Currently processing: {file_path}")
                    
                    for line in f:
                        email = None
                        password = None
                        
                        # Parse email and password from line
                        if ':' in line:
                            parts = line.split(':', 1)
                            email = parts[0]
                            password = parts[1].strip() if len(parts) > 1 else None
                        elif ';' in line:
                            parts = line.split(';', 1)
                            email = parts[0]
                            password = parts[1].strip() if len(parts) > 1 else None
                        else:
                            continue
                        
                        # Extract domain
                        current_domain = extract_domain(email)
                        
                        if current_domain and password:
                            # Track the sequence only if passwords match
                            if prev_domain and prev_password == password:
                                domain_sequences[prev_domain][current_domain] += 1
                            
                            prev_domain = current_domain
                            prev_password = password
                            
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue
    
    print("\nAnalyzing domain sequences...")
    return analyze_sequences(domain_sequences, dst_file)

def analyze_sequences(domain_sequences, dst_file):
    """Find domains with unusually high follow rates"""
    suspicious_chains = []
    
    for source_domain, following_domains in domain_sequences.items():
        total_follows = sum(following_domains.values())
        
        # Check if we have enough data
        if total_follows >= total_follow_threshhold:
            # Find the most common following domain
            max_domain = max(following_domains.items(), key=lambda x: x[1])
            max_following_domain, max_count = max_domain
            
            # Calculate percentage
            percentage = (max_count / total_follows) * 100
            
            # Check if it's over threshold
            if percentage >= follow_percent_threshhold:
                print(f"Found suspicious pattern: {source_domain} -> {max_following_domain} ({percentage:.1f}%)")
                
                # Follow the trail
                chain = trace_chain(source_domain, domain_sequences)
                suspicious_chains.append(chain)
    
    # Export results
    suspicious_chains = export_chains(suspicious_chains, dst_file)
    return suspicious_chains

def trace_chain(start_domain, domain_sequences):
    """Follow the chain of high-probability domain sequences"""
    chain = [start_domain]
    current_domain = start_domain
    visited = {start_domain}  # Prevent infinite loops
    
    while True:
        following_domains = domain_sequences.get(current_domain, {})
        total_follows = sum(following_domains.values())
        
        # Stop if not enough data
        if total_follows <= total_follow_threshhold:
            break
        
        # Find most common following domain
        max_domain = max(following_domains.items(), key=lambda x: x[1])
        next_domain, count = max_domain
        percentage = (count / total_follows) * 100
        
        # Stop if below threshold or already visited
        if percentage <= follow_percent_threshhold or next_domain in visited:
            break
        
        chain.append({
            'domain': next_domain,
            'count': count,
            'total': total_follows,
            'percentage': percentage
        })
        
        visited.add(next_domain)
        current_domain = next_domain
    
    return chain

def generate_subchains(chain):
    """Generate all valid sub-chains from a chain.
    
    For a chain [A, B, C, D, E], generates:
    - [A, B, C, D, E] (full chain)
    - [A, B, C, D]
    - [A, B, C]
    - [B, C, D, E]
    - [B, C, D]
    - [B, C]
    - [C, D, E]
    - [C, D]
    - [D, E]
    
    Only includes sub-chains that meet the minimum length threshold.
    """
    # Extract domain names from the chain
    domains = [chain[0]]  # Start with first domain
    for item in chain[1:]:
        if isinstance(item, dict):
            domains.append(item['domain'])
    
    subchains = []
    chain_len = len(domains)
    
    # Generate all contiguous sub-chains
    for start in range(chain_len):
        for end in range(start + chain_length_threshhold, chain_len + 1):
            subchain = domains[start:end]
            if len(subchain) >= chain_length_threshhold:
                subchains.append(subchain)
    
    return subchains

def export_chains(chains, dst_file):
    """Export suspicious chains and all their sub-chains to CSV"""
    # Filter out chains that don't meet length threshold
    chains = [chain for chain in chains if len(chain) >= chain_length_threshhold]
    
    if not chains:
        print(f"No suspicious patterns found (chains must be at least {chain_length_threshhold} domains long).")
        return []
    
    # Create destination directory if it doesn't exist
    os.makedirs(dst_file, exist_ok=True)
    
    # Export summary file
    summary_path = os.path.join(dst_file, "suspicious_chains_summary.csv")
    with open(summary_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Chain_ID', 'Starting_Domain', 'Chain_Length', 'Full_Chain'])
        
        for idx, chain in enumerate(chains, 1):
            start_domain = chain[0]
            chain_str = start_domain
            
            for item in chain[1:]:
                if isinstance(item, dict):
                    chain_str += f" -> {item['domain']} ({item['percentage']:.1f}%)"
            
            writer.writerow([idx, start_domain, len(chain), chain_str])
    
    print(f"\nSummary exported to: {summary_path}")
    
    # Generate all sub-chains and remove duplicates
    all_subchains = []
    seen_chains = set()
    
    for chain in chains:
        subchains = generate_subchains(chain)
        for subchain in subchains:
            # Convert to tuple for hashability and deduplication
            subchain_tuple = tuple(subchain)
            if subchain_tuple not in seen_chains:
                seen_chains.add(subchain_tuple)
                all_subchains.append(subchain)
    
    print(f"\nGenerated {len(all_subchains)} unique sub-chains from {len(chains)} parent chain(s)")
    
    # Export simple chains file (just domains, comma-separated)
    chains_path = os.path.join(dst_file, "suspicious_chains.csv")
    with open(chains_path, 'w', newline='', encoding='utf-8') as f:
        for subchain in all_subchains:
            # Write as comma-separated values
            f.write(','.join(subchain) + '\n')
    
    print(f"All chains and sub-chains exported to: {chains_path}")
    
    # Also export detailed sub-chains info
    subchains_detail_path = os.path.join(dst_file, "suspicious_chains_detailed.csv")
    with open(subchains_detail_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Chain_Length', 'Starting_Domain', 'Ending_Domain', 'Full_Chain'])
        
        # Sort by length (descending) then alphabetically
        sorted_subchains = sorted(all_subchains, key=lambda x: (-len(x), x[0], x[-1]))
        
        for subchain in sorted_subchains:
            writer.writerow([
                len(subchain),
                subchain[0],
                subchain[-1],
                ' -> '.join(subchain)
            ])
    
    print(f"Detailed sub-chains exported to: {subchains_detail_path}")
    
    return chains

if __name__ == "__main__":
    print("Suspicious Email Group Finder")
    print("=============================\n")
    
    if not os.path.isdir(src):
        print(f"Error: {src} is not a valid directory")
    else:
        chains = find_groups(src, dst)
        print(f"\n\nAnalysis complete. Found {len(chains)} suspicious chain(s).")