# JA4+ Zeek Plugin scripts for data extraction
This repo will be used to share my research regarding the JA4+ plugin on Zeek 7.0.8, Python3, Wireshark 4.4

All information obtained is directly from Foxio under their license. Please see: https://github.com/FoxIO-LLC/ja4?tab=readme-ov-file#running-ja4 for more information. This repository is for research purposes only. 

🐘 Zeek JA4+ Fingerprint Extraction Scripts
Introduction
This repository contains a suite of Python scripts developed as a personal project to enhance the usability and data accessibility of the JA4+ fingerprinting capabilities integrated within a Zeek network security monitor environment.

The official JA4+ Zeek Plugin successfully calculates various JA4+ fingerprints (JA4, JA4S, JA4T, JA4TS, JA4H, JA4X) by modifying standard Zeek logs (e.g., conn.log, ssl.log, http.log, x509.log). These scripts parse the resulting extended Zeek log files, extract the relevant connection details and fingerprints, and output the structured data into user-friendly CSV and JSON formats.

The primary goal of this project is to create an easy, manual process for pulling out key JA4+ data on demand for threat hunting, baselining, and analysis. Future plans include automating these scripts for scheduled, hourly data extraction.

** Attention ** Be congnizant of the following when adjusting to your environment. 

The defualt log path Zeek uses is /opt/zeek/logs/current/ & /opt/zeek/logs/YYYY-MM-DD/ when archived. 
The path to the Current logs in these scripts are /mnt/zeek_logs/current/*.log. Zeek is running off of a mounted flash drive on a Raspberry Pi 4 B+ 

# Please see man_pages for a demonstration on how to use these scripts


For Ja4T (TCP) example output: 

[![j4TCP](ja4t_tcp_output.png)](https://github.com/cisco0pete/JA4_Zeek/blob/main/parse_ja4t_tcp_logs_REV_3.py)


For Ja4H (HTTP) example output: 

[![j4http](ja4h_http_output.png)](https://github.com/cisco0pete/JA4_Zeek/blob/main/parse_ja4h_http_logs_REV_0.py)

For Ja4 & Ja4s (TLS) example output:

[![j4 TLS](ja4_output.png)](https://github.com/cisco0pete/JA4_Zeek/blob/main/parse_ja4s_ssl_log_REV_0.py)

##My goal is to use the Connection ID (UID) property of Zeek to follow an entire connection all the way through. Ultimately, I want to cobble together the entire JA4+ finger print of a connection. Then print out a list of JSON that will easliy identify if this connection is legitimate or not. Perhaps tell me that is a Windows 11 device that is using a fake User-Agent and depricated TLS versions speaking to a known Sliver C2 server (JA4S Fingerprint & other T.I)
