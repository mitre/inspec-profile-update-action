control 'SV-206701' do
  title 'The firewall must employ filters that prevent or limit the effects of all types of commonly known denial-of-service (DoS) attacks, including flooding, packet sweeps, and unauthorized port scanning.'
  desc 'Not configuring a key boundary security protection device such as the firewall against commonly known attacks is an immediate threat to the protected enclave because they are easily implemented by those with little skill. Directions for the attack are obtainable on the Internet and in hacker groups. Without filtering enabled for these attacks, the firewall will allow these attacks beyond the protected boundary.

Configure the perimeter and internal boundary firewall to guard against the three general methods of well-known DoS attacks: flooding attacks, protocol sweeping attacks, and unauthorized port scanning.

Flood attacks occur when the host receives too much traffic to buffer and slows down or crashes. Popular flood attacks include ICMP flood and SYN flood. A TCP flood attack of SYN packets initiating connection requests can overwhelm the device until it can no longer process legitimate connection requests, resulting in denial of service. An ICMP flood can overload the device with so many echo requests (ping requests) that it expends all its resources responding and can no longer process valid network traffic, also resulting in denial of service. An attacker might use session table floods and SYN-ACK-ACK proxy floods to fill up the session table of a host.

In an IP address sweep attack, an attacker sends ICMP echo requests (pings) to multiple destination addresses. If a target host replies, the reply reveals the target’s IP address to the attacker. In a TCP sweep attack, an attacker sends TCP SYN packets to the target device as part of the TCP handshake. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack. In a UDP sweep attack, an attacker sends UDP packets to the target device. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack.

In a port scanning attack, an unauthorized application is used to scan the host devices for available services and open ports for subsequent use in an attack. This type of scanning can be used as a DoS attack when the probing packets are sent excessively.'
  desc 'check', 'View the security filters for each interface or security zone.

Verify DoS filters are configured to detect and prevent known DoS attacks such as IP sweeps, TCP sweeps, buffer overflows, unauthorized port scanning, SYN floods, UDP floods, and UDP sweeps.

If filters are not configured or if the security zone is not configured with filters that guard against common DoS attacks, this is a finding.'
  desc 'fix', 'Configure the firewall to detect and prevent DoS attacks. Implement filters with thresholds that are customized for the specific environment where applicable. DoS filters are based on NIST 800-53 requirements and vendor recommendations.

The following sample commands show filters that implement this requirement (these are examples only):

set filter1 icmp ip-sweep threshold 1000
set filter2 tcp port-scan threshold 1000
set filter3 tcp syn-flood alarm-threshold 1000
set filter3 tcp syn-flood attack-threshold 1100
set filter4 tcp syn-flood source-threshold 100
set filter5 tcp syn-flood destination-threshold 2048
set filter6 tcp syn-flood timeout 20
set filter7 tcp tcp-sweep threshold 1000
set filter8 udp flood threshold 5000
set filter9 udp udp-sweep threshold 1000'
  impact 0.7
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6958r297882_chk'
  tag severity: 'high'
  tag gid: 'V-206701'
  tag rid: 'SV-206701r604133_rule'
  tag stig_id: 'SRG-NET-000362-FW-000028'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-6958r297883_fix'
  tag 'documentable'
  tag legacy: ['V-79413', 'SV-94119']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
