control 'SV-228860' do
  title 'The Palo Alto Networks security platform must protect against Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis (traffic thresholds).'
  desc 'If the network does not provide safeguards against DoS attacks, network resources may be unavailable to users. Installation of content filtering gateways and application-layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks that are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.

PAN-OS can use either Zone-Based Protection or End Host Protection to mitigate DoS attacks.  Zone-Based Protection protects against most common floods, reconnaissance attacks and other packet-based attacks and is applied to any zone.  End Host Protection is specific to defined end hosts.

It is important to set the Flood Protection parameters that are suitable for the enclave or system.  The Administrator should characterize the traffic regularly (perform a traffic baseline) and tune these parameters based on that information.'
  desc 'check', 'Ask the Administrator if the device is using a Zone-Based Protection policy or a DoS Protection policy.

If it is using a Zone-Based Protection policy, perform the following:
Go to Network >> Network Profiles >> Zone Protection
If there are no Zone Protection Profiles configured, this is a finding.

There may be more than one configured Zone Protection Profile; ask the Administrator which Zone Protection Profile is intended to protect inside networks and DMZ networks from externally-originated DoS attacks.
Go to Network >> Zones
If the "Zone Protection Profile" column for the Internal zone or the DMZ is blank, this is a finding.
If it lists an incorrect Zone Protection Profile, this is also a finding.

If it is using a DoS Protection policy, perform the following:
Go to Objects >> Security Profiles >> DoS Protection
There may be more than one configured DoS Protection Policy; ask the Administrator which  DoS Protection Policy is intended to protect internal networks and DMZ networks from externally-originated DoS attacks. 
Go to Policies >> DoS Protection
If there is no DoS Protection Policy to protect internal networks and DMZ networks from externally-originated DoS attacks, this is a finding.
If the DoS Protection Policy has no DoS Protection Profile, this is a finding.'
  desc 'fix', %q(Configure either a Zone-Based Protection policy or a DoS Protection policy.
To configure a Zone-Based Protection policy, perform the following:
Go to Network >> Network Profiles >> Zone Protection
Select "Add".
In the "Zone Protection Profile" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Flood Protection" tab, select the "Syn" check box, in the "Action" field, select either "Random Early Drop" (preferred in this case) or "SYN Cookie"; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "ICMP" check box; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "ICMPv6" check box; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "Other IP" check box; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "UDP" check box; complete the "Alert", "Activate", and "Maximum" fields.
For each of the "Alert", "Activate", and "Maximum" fields, the appropriate values depends on the expected traffic of the system. 
In the "Reconnaissance Protection" tab, select the "TCP Port Scan", "Host Sweep", and "UDP Port Scan" rows.
In the "Action" field, Select "Block". The Interval and Threshold values can either remain as the default values or they can be changed based on the specific traffic conditions of the network.
In the "Packet Based Attack Protection" tab, "TCP/IP Drop" tab, select the "Spoofed IP address", "Mismatched overlapping TCP segment" check boxes.
In the "TCP/IP Drop" tab, select the "Strict Source Routing", "Loose Source Routing", "Timestamp", "Unknown", and "Malformed" check boxes.
The "Security" and "Stream ID" check boxes can remain unchecked.
For the "Reject Non-SYN TCP" field, select "yes".
For the "Asymmetric Path" field, select "bypass".
In the "ICMP Drop" tab, select the "ICMP Ping ID 0, ICMP Fragment", "ICMP Large Packet(>1024)" check boxes.
The "Suppress ICMP TTL Expired Error", and "Suppress ICMP Frag Needed" check boxes can remain unchecked unless this profile will be applied to an internal or DMZ.
In the "IPv6 Drop" tab, select the "Type 0 Routing Header", "IPv4 compatible address", "Anycast source address", "Needless fragment header", "MTU in ICMPv6 'Packet Too Big' less than 1280 bytes", "Hop-by-Hop extension", "Routing extension", "Destination extension", "Invalid IPv6 options in extension header", and "Non-zero reserved field" check boxes.
In the "ICMPv6" tab, select the "ICMPv6 destination unreachable", "ICMPv6 packet too big", "ICMPv6 time exceeded", "ICMPv6 parameter problem", and "ICMPv6 redirect" check boxes.
Select "OK".

Apply the Zone Protection Profile to the internal zone and the DMZ:
Go to Network >> Zones
Select the internal zone.
In the "Zone" window, in the "Zone Protection Profile" window, select the configured Zone Protection Profile.
Select "OK".
Go to Network >> Zones
Select the DMZ.
In the "Zone" window, in the "Zone Protection Profile" window, select the configured Zone Protection Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.

To configure a DoS Protection policy, perform the following:
Go to Objects >> Security Profiles >> DoS Protection
Select "Add" to create a new profile.
In the "DoS Protection Profile" window, complete the required fields.
For the "Type", select "Classified".
In the "Flood Protection" tab, "Syn Flood" tab, select the "Syn Flood" check box and select "SYN Cookie". 
In the "Flood Protection" tab, "UDP Flood" tab, select the "UDP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMP Flood" tab, select the "ICMP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMPv6 Flood" tab, select the "ICMPv6 Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
In the "Flood Protection" tab, "Other IP Flood" tab, select the "Other IP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
In the "Resources Protection" tab, select the "Maximum Concurrent Sessions" check box.
In the "Resources Protection" tab, complete the "Max Concurrent Sessions" field. If the DoS profile type is aggregate, this limit applies to the entire traffic hitting the DoS rule on which the DoS profile is applied.
If the DoS profile type is classified, this limit applies to the entire traffic on a classified basis (source IP, destination IP or source-and-destination IP) hitting the DoS rule on which the DoS profile is applied.
Select "OK".

Go to Policies >> DoS Protection
Select "Add" to create a new policy.
In the "DoS Rule" Window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, for "Zone", select the "External zone", for "Source Address", select "Any".
In the "Destination" tab, "Zone", select "Internal zone", for "Destination Address", select "Any".
In the "Option/Protection" tab, 
For "Service", select "Any".
For "Action", select "Protect".
Select the "Classified" check box.
In the "Profile" field, select the configured DoS Protection profile for inbound traffic.
In the "Address" field, select destination-ip-only.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31095r513875_chk'
  tag severity: 'high'
  tag gid: 'V-228860'
  tag rid: 'SV-228860r557387_rule'
  tag stig_id: 'PANW-AG-000102'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-31072r513876_fix'
  tag 'documentable'
  tag legacy: ['V-62601', 'SV-77091']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
