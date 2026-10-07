import os
import io
import requests
import csv
from datetime import datetime
import time
import random
from sqlfuzzer import SqlFuzzer  # Import your fuzzer class
from xssfuzzer import XssFuzzer
from dataset_analyzer import analyze_dataset


def print_dataset_analysis(report, analysis_dir):
    summary = report['summary']
    statistics = report['payload_statistics']
    labels = ', '.join(f"{label}: {count}" for label, count in summary['labels'].items())

    print("\n" + "=" * 64)
    print("DATASET ANALYSIS")
    print("=" * 64)
    print(f"Verdict                  : {report['verdict']}")
    print(f"Overall score            : {report['score']}/100")
    print(f"Total / valid rows       : {summary['total_rows']} / {summary['valid_rows']}")
    print(f"Missing payloads/labels  : {summary['missing_payloads']} / {summary['missing_labels']}")
    print(f"Label distribution       : {labels or 'No labels found'}")
    print(f"Exact duplicate rows     : {summary['exact_duplicate_rows']}")
    print(f"Canonical duplicate rows : {summary['canonical_duplicate_rows']}")
    print(f"Conflicting labels       : {summary['conflicting_canonical_payloads']}")
    print(f"Mean character entropy   : {statistics['character_entropy_mean_bits']} bits")
    print(f"Whole-file byte entropy  : {report['file_entropy']['whole_file_bits_per_byte']} bits/byte")
    print(f"Chunk entropy mean/range : {report['file_entropy']['chunk_mean_bits_per_byte']} "
          f"({report['file_entropy']['chunk_min_bits_per_byte']}-"
          f"{report['file_entropy']['chunk_max_bits_per_byte']}) bits/byte")
    category_coverage = report['attack_category_coverage']
    if category_coverage['available']:
        print(f"Attack categories        : {category_coverage['distinct_categories']}")
    else:
        print("Attack categories        : unavailable (no category column)")
    print("\nQuality scores:")
    for metric in report['metrics']:
        print(f"  - {metric['name']:<20} {metric['score']:>6.2f}/100  [{metric['status']}]")
    if report['critical_findings']:
        print("\nCritical findings:")
        for finding in report['critical_findings']:
            print(f"  - {finding}")
    print(f"\nFull reports             : {analysis_dir}")
    print("=" * 64 + "\n", flush=True)

# Function to wait until services are ready (if needed)
def wait_until_services_ready():
    time.sleep(5)  # Adjust the delay as needed based on your Docker service startup time


def print_run_configuration(payloads_file, fuzzer_type, ml_provider, num_samples,
                            num_fuzzing_rounds, payload_scope, max_mutated_length):
    """Print the exact experiment configuration before requests are sent."""
    print("\n" + "=" * 64)
    print("EXPERIMENT CONFIGURATION")
    print("=" * 64)
    print(f"Dataset                  : {os.path.basename(payloads_file)}")
    print(f"Dataset path             : {payloads_file}")
    print(f"Fuzzer                   : {fuzzer_type}")
    print("ML firewall              : "
          f"{ml_provider} (ml_waf)")
    print("RB firewall              : ModSecurity/Apache (rb_waf)")
    print(f"Original samples         : {num_samples}")
    print(f"Fuzzing rounds/sample    : {num_fuzzing_rounds}")
    print(f"Payload scope            : {payload_scope}")
    print(f"Max mutated length       : {max_mutated_length}")
    print("=" * 64 + "\n", flush=True)

# Function to send request to server and return the results
def send_request(payload):
    url = 'http://server:5000/request'  # Adjust server URL as needed
    data = {
        'payload': payload.strip()  # Remove any trailing newline characters
    }
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            waf_status_code = response.json().get('WAF_status_code', 'Unknown')
            ml_status_code = response.json().get('ML_status_code', 'Unknown')
        else:
            waf_status_code = response.status_code
            ml_status_code = 'Error'
        
        # Return status codes
        return waf_status_code, ml_status_code
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return 'Error: Connection failed', 'Error: Connection failed'

# Function to determine TP, TN, FP, FN
def determine_metrics(original_status, predicted_status):
    if original_status == 403:
        if predicted_status == 403:
            return 'TP'
        else:
            return 'FN'
    else:
        if predicted_status == 200:
            return 'TN'
        else:
            return 'FP'

# Function to determine if the predictions from WAF and ML match
def determine_combined_result(original_status, waf_status, ml_status):
    waf_metric = determine_metrics(original_status, waf_status)
    ml_metric = determine_metrics(original_status, ml_status)
    
    if (waf_metric in ['TP', 'TN']) and (ml_metric in ['TP', 'TN']):
        return 'both_correct'
    elif (waf_metric in ['FP', 'FN']) and (ml_metric in ['FP', 'FN']):
        return 'both_incorrect'
    elif (waf_metric in ['TP', 'TN']) and (ml_metric in ['FP', 'FN']):
        return 'waf_correct_ml_incorrect'
    else:
        return 'waf_incorrect_ml_correct'


def _find_column(fieldnames, candidates):
    """Find a CSV column case-insensitively, including common aliases."""
    lookup = {(name or '').strip().lower(): name for name in fieldnames or []}
    return next((lookup[name] for name in candidates if name in lookup), None)


def _status_code(value):
    """Normalize HTTP labels and common benign/malicious class labels."""
    normalized = str(value or '').strip().lower()
    if normalized in {'malicious', 'malware', 'attack', 'anomalous', 'anomaly', 'true', '1', '403'}:
        return 403
    if normalized in {'benign', 'normal', 'legitimate', 'safe', 'false', '0', '200'}:
        return 200
    try:
        code = int(normalized)
    except ValueError as error:
        raise ValueError(
            f"Unsupported dataset label '{value}'. Use 200/403 or "
            "Benign/Malicious labels."
        ) from error
    return code


def load_payloads(payloads_file):
    """Load SQL-style and XSS-style datasets into (payload, expected_status)."""
    payload_columns = ('payload', 'payloads', 'request', 'text', 'input', 'query')
    label_columns = ('status code', 'status_code', 'status', 'label', 'class', 'target')

    with open(payloads_file, 'rb') as source:
        raw = source.read()
    text = None
    for encoding in ('utf-8-sig', 'cp1252', 'latin-1'):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise ValueError(f"Dataset '{payloads_file}' uses an unsupported text encoding.")

    reader = csv.DictReader(io.StringIO(text, newline=''))
    payload_column = _find_column(reader.fieldnames, payload_columns)
    label_column = _find_column(reader.fieldnames, label_columns)
    if not payload_column or not label_column:
        raise ValueError(
            f"Dataset '{payloads_file}' must contain a payload column and "
            f"a status/label column. Found: {reader.fieldnames or []}"
        )

    payloads = []
    for row_number, row in enumerate(reader, start=2):
        payload = (row.get(payload_column) or '').strip()
        if not payload:
            continue
        try:
            status = _status_code(row.get(label_column))
        except ValueError as error:
            raise ValueError(f"{payloads_file}, row {row_number}: {error}") from error
        payloads.append([payload, status])

    if not payloads:
        raise ValueError(f"Dataset '{payloads_file}' contains no valid payload rows.")
    return payloads

# Function to run the main process
def main():
    payloads_file = os.getenv('PAYLOADS_FILE', 'payloads.csv')
    analysis_dir = os.getenv('DATASET_ANALYSIS_DIR', 'Dataset Analysis')
    ml_provider = os.getenv('ML_WAF_PROVIDER', 'wafbrain').strip().lower()
    num_samples = int(os.getenv('NUM_SAMPLES', 10))
    num_fuzzing_rounds = int(os.getenv('NUM_FUZZING_ROUNDS', 5))
    fuzzer_type = os.getenv('FUZZER_TYPE', 'sql').strip().lower()
    payload_scope = os.getenv('PAYLOAD_SCOPE', 'malicious_only').strip().lower()
    max_mutated_length = int(os.getenv('MAX_MUTATED_LENGTH', 2048))
    if max_mutated_length < 128:
        raise ValueError("MAX_MUTATED_LENGTH must be at least 128.")
    if payload_scope not in ('malicious_only', 'both'):
        raise ValueError("PAYLOAD_SCOPE must be 'malicious_only' or 'both'.")
    print_run_configuration(
        payloads_file,
        'xss' if fuzzer_type in ('xss', 'html', 'javascript') else 'sql',
        ml_provider,
        num_samples,
        num_fuzzing_rounds,
        payload_scope,
        max_mutated_length,
    )
    analyze_dataset_enabled = os.getenv('ANALYZE_DATASET', 'yes').strip().lower() in ('1', 'true', 'yes', 'on')
    if analyze_dataset_enabled:
        report = analyze_dataset(payloads_file, analysis_dir)
        print_dataset_analysis(report, analysis_dir)
    else:
        print("Dataset analysis skipped (ANALYZE_DATASET=no)", flush=True)

    wait_until_services_ready()  # Wait for services to start up

    fuzzer_class = XssFuzzer if fuzzer_type in ('xss', 'html', 'javascript') else SqlFuzzer
    print(f"Fuzzer mode: {'xss' if fuzzer_class is XssFuzzer else 'sql'}", flush=True)

    payloads = load_payloads(payloads_file)

    if payload_scope == 'malicious_only':
        payloads = [row for row in payloads if row[1] == 403]
        if not payloads:
            raise ValueError(
                f"Dataset '{payloads_file}' contains no malicious (403) payloads "
                "for PAYLOAD_SCOPE=malicious_only."
            )

    # Select a random sample of payloads
    sample_payloads = random.sample(payloads, min(num_samples, len(payloads)))

    with open('logs/client_logs.csv', mode='w', newline='') as log_file:
        writer = csv.writer(log_file)
        # Persist the experiment configuration in the log so each CSV is
        # self-describing, even when Docker stdout is not retained.
        writer.writerow(['Experiment Configuration'])
        writer.writerow(['Run timestamp', datetime.now().isoformat()])
        writer.writerow(['Dataset', os.path.basename(payloads_file)])
        writer.writerow(['Dataset path', payloads_file])
        writer.writerow(['Fuzzer', 'xss' if fuzzer_type in ('xss', 'html', 'javascript') else 'sql'])
        writer.writerow(['ML firewall', ml_provider])
        writer.writerow(['RB firewall', 'ModSecurity/Apache (rb_waf)'])
        writer.writerow(['Original samples', num_samples])
        writer.writerow(['Fuzzing rounds per sample', num_fuzzing_rounds])
        writer.writerow(['Payload scope', payload_scope])
        writer.writerow(['Max mutated length', max_mutated_length])
        writer.writerow([])

        # Write the payload-result header row
        header = ['Sr NO.', 'Original Timestamp', 'Payload', 'Original Status', 'WAF Status', 'ML Status', 'Combined Result']
        for i in range(1, num_fuzzing_rounds + 1):
            header.extend([
                f'Fuzzed Payload {i}', f'Fuzzed Timestamp {i}',
                f'Mutation Operator {i}', f'Mutation Validation {i}',
                f'WAF Status {i}', f'ML Status {i}',
                f'Combined Result {i}'
            ])
        writer.writerow(header)
        
        serial_number = 1
        
        # Initialize counters for WAF and ML metrics
        waf_tp, waf_tn, waf_fp, waf_fn = 0, 0, 0, 0
        ml_tp, ml_tn, ml_fp, ml_fn = 0, 0, 0, 0

        # Initialize counters for the confusion matrix
        both_correct = 0
        both_incorrect = 0
        waf_correct_ml_incorrect = 0
        waf_incorrect_ml_correct = 0

        for idx, row in enumerate(sample_payloads, start=1):
            original_payload = row[0]
            original_status = int(row[1])  # Ensure original status is an integer
            original_timestamp = datetime.now().isoformat()
            waf_status_code, ml_status_code = send_request(original_payload)  # Send original payload
            
            # Determine WAF and ML metrics for the original payload
            waf_metric = determine_metrics(original_status, waf_status_code)
            ml_metric = determine_metrics(original_status, ml_status_code)
            
            # Update WAF metrics
            if waf_metric == 'TP':
                waf_tp += 1
            elif waf_metric == 'TN':
                waf_tn += 1
            elif waf_metric == 'FP':
                waf_fp += 1
            elif waf_metric == 'FN':
                waf_fn += 1
            
            # Update ML metrics
            if ml_metric == 'TP':
                ml_tp += 1
            elif ml_metric == 'TN':
                ml_tn += 1
            elif ml_metric == 'FP':
                ml_fp += 1
            elif ml_metric == 'FN':
                ml_fn += 1

            # Determine combined result for original payload
            combined_result = determine_combined_result(original_status, waf_status_code, ml_status_code)
            if combined_result == 'both_correct':
                both_correct += 1
            elif combined_result == 'both_incorrect':
                both_incorrect += 1
            elif combined_result == 'waf_correct_ml_incorrect':
                waf_correct_ml_incorrect += 1
            elif combined_result == 'waf_incorrect_ml_correct':
                waf_incorrect_ml_correct += 1

            # Log the result
            log_entry = [serial_number, original_timestamp, original_payload, original_status, waf_status_code, ml_status_code, combined_result]
            
            # Generate and send fuzzed payloads
            if fuzzer_class is XssFuzzer:
                fuzzer = fuzzer_class(original_payload, max_length=max_mutated_length)
            else:
                fuzzer = fuzzer_class(original_payload)
            for i in range(1, num_fuzzing_rounds + 1):
                fuzzed_payload = fuzzer.fuzz()  # Fuzz the payload
                fuzzed_timestamp = datetime.now().isoformat()
                fuzzed_waf_status_code, fuzzed_ml_status_code = send_request(fuzzed_payload)  # Send fuzzed payload
                
                # Determine WAF and ML metrics for fuzzed payload
                fuzzed_waf_metric = determine_metrics(original_status, fuzzed_waf_status_code)
                fuzzed_ml_metric = determine_metrics(original_status, fuzzed_ml_status_code)
                
                # Update WAF metrics
                if fuzzed_waf_metric == 'TP':
                    waf_tp += 1
                elif fuzzed_waf_metric == 'TN':
                    waf_tn += 1
                elif fuzzed_waf_metric == 'FP':
                    waf_fp += 1
                elif fuzzed_waf_metric == 'FN':
                    waf_fn += 1

                # Update ML metrics
                if fuzzed_ml_metric == 'TP':
                    ml_tp += 1
                elif fuzzed_ml_metric == 'TN':
                    ml_tn += 1
                elif fuzzed_ml_metric == 'FP':
                    ml_fp += 1
                elif fuzzed_ml_metric == 'FN':
                    ml_fn += 1

                # Determine combined result for fuzzed payload
                fuzzed_combined_result = determine_combined_result(original_status, fuzzed_waf_status_code, fuzzed_ml_status_code)
                if fuzzed_combined_result == 'both_correct':
                    both_correct += 1
                elif fuzzed_combined_result == 'both_incorrect':
                    both_incorrect += 1
                elif fuzzed_combined_result == 'waf_correct_ml_incorrect':
                    waf_correct_ml_incorrect += 1
                elif fuzzed_combined_result == 'waf_incorrect_ml_correct':
                    waf_incorrect_ml_correct += 1

                operator = getattr(fuzzer, 'last_operator', 'sql_mutation')
                validation = getattr(fuzzer, 'last_validation', 'not_applicable')
                log_entry.extend([
                    fuzzed_payload, fuzzed_timestamp, operator, validation,
                    fuzzed_waf_status_code, fuzzed_ml_status_code,
                    fuzzed_combined_result
                ])
                
                # Pause between requests if needed
                time.sleep(1)
            
            writer.writerow(log_entry)  # Write the log entry
            serial_number += 1

        # Save overall results to the log file
        writer.writerow([])
        writer.writerow(['Overall Results'])
        writer.writerow(['WAF TP', waf_tp])
        writer.writerow(['WAF TN', waf_tn])
        writer.writerow(['WAF FP', waf_fp])
        writer.writerow(['WAF FN', waf_fn])
        writer.writerow(['ML TP', ml_tp])
        writer.writerow(['ML TN', ml_tn])
        writer.writerow(['ML FP', ml_fp])
        writer.writerow(['ML FN', ml_fn])

        # Save combined prediction results to the log file as a 2x2 confusion matrix
        writer.writerow([])
        writer.writerow(['Combined Results (2x2 Matrix)'])
        writer.writerow(['', 'RB Correct', 'RB Incorrect'])
        writer.writerow(['ML Correct', both_correct, waf_incorrect_ml_correct])
        writer.writerow(['ML Incorrect', waf_correct_ml_incorrect, both_incorrect])

        # Print the combined prediction results as a 2x2 confusion matrix
        print("\nCombined Results (2x2 Matrix):")
        print(f"{'':<15}{'RB Correct':<15}{'RB Incorrect':<15}")
        print(f"{'ML Correct':<15}{both_correct:<15}{waf_incorrect_ml_correct:<15}")
        print(f"{'ML Incorrect':<15}{waf_correct_ml_incorrect:<15}{both_incorrect:<15}")

if __name__ == "__main__":
    main()
