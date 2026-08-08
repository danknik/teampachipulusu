# Forensics CTF Automation Toolkit

## Full Analysis (one command per evidence type)

```bash
./network/pcap_analyze.sh capture.pcap
./memory/mem_analyze.sh memory.raw
./disk/disk_analyze.sh disk.img
```

## Network Scripts

```bash
./network/pcap_analyze.sh <pcap_file>                # runs all below in sequence
./network/pcap_analyze.sh <pcap_file> --skip-streams  # skip stream reassembly (faster)

./network/export_objects.sh <pcap_file>               # extract transferred files
./network/cred_grabber.sh <pcap_file>                 # extract credentials
./network/dns_exfil.sh <pcap_file>                    # detect DNS exfiltration
./network/conv_stats.sh <pcap_file>                   # conversation & protocol stats
./network/stream_extract.sh <pcap_file>               # reassemble all TCP/UDP streams
```

## Memory Scripts

```bash
./memory/mem_analyze.sh <dump_file>                   # runs all below in sequence
./memory/mem_analyze.sh <dump_file> --skip-filedump   # skip file extraction
./memory/mem_analyze.sh <dump_file> --skip-strings    # skip string search

./memory/vol3_runner.sh <dump_file>                   # volatility 3 plugin battery
./memory/proc_dumper.sh <dump_file> <vol3_output_dir> # dump suspicious processes
./memory/file_extractor.sh <dump_file> <vol3_output_dir> # extract file objects
./memory/mem_strings.sh <dump_file>                   # string/regex search
```

## Disk Scripts

```bash
./disk/disk_analyze.sh <image_file>                   # runs all below in sequence
./disk/disk_analyze.sh <image_file> --skip-stego      # skip steganography scan
./disk/disk_analyze.sh <image_file> --skip-recovery   # skip deleted file recovery
./disk/disk_analyze.sh <image_file> --skip-timeline   # skip timeline generation

./disk/carve.sh <image_file>                          # recursive file carving
./disk/timeline.sh <image_file>                       # filesystem timeline
./disk/recover_deleted.sh <image_file>                # deleted file recovery
./disk/metadata_sweep.sh <target_dir>                 # EXIF/metadata extraction
./disk/stego_scan.sh <target_dir>                     # steganography detection
```


