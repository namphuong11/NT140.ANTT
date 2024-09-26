# from scapy.all import rdpcap, IP, Raw

# # Đọc file pcap
# packets = rdpcap('attack.pcap')

# # Địa chỉ IP của kẻ tấn công
# attacker_ip = "10.150.109.181"  # Thay bằng IP của kẻ tấn công

# # Duyệt qua các gói tin để trích xuất payload
# with open('output.txt', 'w') as f:
#     for pkt in packets:
#         if pkt.haslayer(IP) and pkt[IP].src == attacker_ip:
#             protocol = None
#             if pkt.haslayer("TCP"):
#                 protocol = 'TCP'
#             elif pkt.haslayer("UDP"):
#                 protocol = 'UDP'
#             elif pkt.haslayer("ICMP"):
#                 protocol = 'ICMP'
            
#             if pkt.haslayer(Raw):  # Tìm payload thô trong gói tin
#                 payload = pkt[Raw].load
#                 try:
#                     f.write(f'Protocol: {protocol}\n')
#                     f.write(payload.decode('ascii') + '\n')  # Chuyển đổi payload sang ASCII và ghi vào file
#                 except UnicodeDecodeError:
#                     pass
# Đọc file output.txt
with open('output.txt', 'r') as f:
    lines = f.readlines()

# Các từ khóa liên quan đến camera
keywords = ['/admin', '/login', '/config', '/camera', '/video']

# Mở file anomoly.txt để ghi kết quả
with open('anomoly.txt', 'w') as anomaly_file:
    # Duyệt qua các dòng và tìm kiếm các từ khóa
    for i, line in enumerate(lines):
        for keyword in keywords:
            if keyword in line:
                anomaly_file.write(f"Found keyword '{keyword}' on line {i+1}: {line.strip()}\n")
                # Ghi thêm các dòng liên quan để có ngữ cảnh
                for j in range(i+1, min(i+6, len(lines))):
                    anomaly_file.write(lines[j].strip() + '\n')
                anomaly_file.write('\n')