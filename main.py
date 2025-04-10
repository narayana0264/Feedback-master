import os

def main():
    os.system("python scripts/sniff_live.py")
    os.system("python scripts/process_pcap.py")
    os.system("python scripts/extract_features.py")

if __name__ == "__main__":
    main()
