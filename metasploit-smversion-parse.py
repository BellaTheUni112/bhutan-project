import re
import csv
import argparse

ansi_clean = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

def clean(line):
    return ansi_clean.sub("", line).strip()

def get_ip(line):
    m = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+)", line)
    return m.group(1) if m else None

def extract_smb(line):
    m = re.search(r"SMB Detected \(versions: ([^)]+)\)", line)
    return f"SMB versions: {m.group(1)}" if m else ""

def extract_os(line):
    m = re.search(r"Host is running (.+)", line)
    return m.group(1).strip() if m else ""

def extract_signing(line):
    m = re.search(r"SMB signing (.+)", line)
    return m.group(1).strip() if m else ""


def parse_file(file_in):
    data = {}
    current_ip = None

    with open(file_in, "r", errors="ignore") as f:
        for line in f:
            line = clean(line)

            ip = get_ip(line)
            if ip:
                current_ip = ip
                data.setdefault(ip, {"smb": "", "os": "", "signing": ""})

            if not current_ip:
                continue

            smb = extract_smb(line)
            if smb:
                data[current_ip]["smb"] = smb

            os_info = extract_os(line)
            if os_info:
                data[current_ip]["os"] = os_info

            signing = extract_signing(line)
            if signing:
                data[current_ip]["signing"] = signing

    return data


def write_txt(data, path):
    with open(path, "w") as f:
        for ip, d in sorted(data.items()):
            f.write(
                f"{ip}\n"
                f"  {d['smb']}\n"
                f"  OS: {d['os']}\n"
                f"  SMB Signing: {d['signing']}\n\n"
            )


def write_csv(data, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "SMB Versions", "OS", "SMB Signing"])

        for ip, d in sorted(data.items()):
            writer.writerow([ip, d["smb"], d["os"], d["signing"]])


def main():
    parser = argparse.ArgumentParser(description="SMB scan log parser")
    parser.add_argument("--input", required=True, help="Input log file")
    parser.add_argument("--txt", default="smb_report.txt", help="Output TXT file")
    parser.add_argument("--csv", default="smb_report.csv", help="Output CSV file")

    args = parser.parse_args()

    data = parse_file(args.input)

    write_txt(data, args.txt)
    write_csv(data, args.csv)

    print(f"Done.")
    print(f"TXT: {args.txt}")
    print(f"CSV: {args.csv}")
    print(f"Hosts parsed: {len(data)}")


if __name__ == "__main__":
    main()
