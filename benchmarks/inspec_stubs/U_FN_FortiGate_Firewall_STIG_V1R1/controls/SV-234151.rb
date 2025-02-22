control 'SV-234151' do
  title 'The FortiGate firewall must employ filters that prevent or limit the effects of all types of commonly known denial-of-service (DoS) attacks, including flooding, packet sweeps, and unauthorized port scanning.'
  desc 'Not configuring a key boundary security protection device such as the firewall against commonly known attacks is an immediate threat to the protected enclave because they are easily implemented by those with little skill. Directions for the attack are obtainable on the internet and in hacker groups. Without filtering enabled for these attacks, the firewall will allow these attacks beyond the protected boundary.

Configure the perimeter and internal boundary firewall to guard against the three general methods of well-known DoS attacks: flooding attacks, protocol sweeping attacks, and unauthorized port scanning.

Flood attacks occur when the host receives too much traffic to buffer and slows down or crashes. Popular flood attacks include ICMP flood and SYN flood. A TCP flood attack of SYN packets initiating connection requests can overwhelm the device until it can no longer process legitimate connection requests, resulting in DoS. An ICMP flood can overload the device with so many echo requests (ping requests) that it expends all its resources responding and can no longer process valid network traffic, also resulting in DoS. An attacker might use session table floods and SYN-ACK-ACK proxy floods to fill up the session table of a host.

In an IP address sweep attack, an attacker sends ICMP echo requests (pings) to multiple destination addresses. If a target host replies, the reply reveals the target’s IP address to the attacker. In a TCP sweep attack, an attacker sends TCP SYN packets to the target device as part of the TCP handshake. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack. In a UDP sweep attack, an attacker sends UDP packets to the target device. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack.

In a port scanning attack, an unauthorized application is used to scan the host devices for available services and open ports for subsequent use in an attack. This type of scanning can be used as a DoS attack when the probing packets are sent excessively.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 DoS Policy.
3. Verify different DoS policies that include Incoming Interface, Source Address, Destination Address, and Services have been created.
4. Double-.click on each policy.
5. Verify the DS policies are configured with appropriate thresholds for L3 and L4 anomalies.

If the DoS policies are not configured to filter packets associated with flooding, packet sweeps, and unauthorized port scanning, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 DoS Policy or IPv6 DoS Policy.
3. Click +Create New.
4. Configure DoS policies that include Incoming Interface, Source Address, Destination Address, and Services.
5. Configure Action and Threshold for L3 and L4 anomalies per site policies.
6. Click OK.'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37336r611451_chk'
  tag severity: 'high'
  tag gid: 'V-234151'
  tag rid: 'SV-234151r628776_rule'
  tag stig_id: 'FNFG-FW-000110'
  tag gtitle: 'SRG-NET-000362-FW-000028'
  tag fix_id: 'F-37301r611452_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
