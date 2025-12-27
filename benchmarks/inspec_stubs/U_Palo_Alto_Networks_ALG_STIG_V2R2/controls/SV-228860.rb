control 'SV-228860' do
  title 'The Palo Alto Networks security platform must protect against Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis (traffic thresholds).'
  desc 'If the network does not provide safeguards against DoS attacks, network resources may be unavailable to users. Installation of content filtering gateways and application-layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks that are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.

PAN-OS can use either Zone-Based Protection or End Host Protection to mitigate DoS attacks.  Zone-Based Protection protects against most common floods, reconnaissance attacks and other packet-based attacks and is applied to any zone.  End Host Protection is specific to defined end hosts.

It is important to set the Flood Protection parameters that are suitable for the enclave or system.  The Administrator should characterize the traffic regularly (perform a traffic baseline) and tune these parameters based on that information.'
  desc 'check', 'Ask the Administrator if the device is using a Zone-Based Protection policy or a DoS Protection policy.
If it is using a Zone-Based Protection policy, perform the following:
Go to Network >> Network Profiles >> Zone Protection.
If there are no Zone Protection Profiles configured, this is a finding.

Note: There may be more than one configured Zone Protection Profile; ask the Administrator which Zone Protection Profile is intended to protect inside networks and DMZ networks from externally-originated DoS attacks.
Go to Network >> Zones.
If the "Zone Protection Profile" column for the internal zone or the DMZ is blank, this is a finding.
If it lists an incorrect Zone Protection Profile, this is also a finding.

If it is using a DoS Protection policy, perform the following:
Go to Objects >> Security Profiles >> DoS Protection.
There may be more than one configured DoS Protection Policy; ask the Administrator which DoS Protection Policy is intended to protect internal networks and DMZ networks from externally-originated DoS attacks. 
Go to Policies >> DoS Protection.
If there is no DoS Protection Policy to protect internal networks and DMZ networks from externally-originated DoS attacks, this is a finding.
If the DoS Protection Policy has no DoS Protection Profile, this is a finding.'
  desc 'fix', %q(Configure either a Zone-Based Protection policy or a DoS Protection policy. 
To configure a Zone-Based Protection policy, perform the following:
1.	Go to Network >> Network Profiles >> Zone Protection and select "Add".
2.	In the "Zone Protection Profile" window, complete the required fields.
3.	In the "General" tab, complete the "Name" and "Description" fields.
4.	Configure Flood Protection:
a. In the "Flood Protection" tab, select the "Syn" check box, in the "Action" field, select either "Random Early Drop" (preferred in this case) or "SYN Cookie"; complete the "Alert", "Activate", and "Maximum" fields. 
b. In the "Flood Protection" tab, select the "ICMP" check box; complete the "Alert", "Activate", and "Maximum" fields. 
c. In the "Flood Protection" tab, select the "ICMPv6" check box; complete the "Alert", "Activate", and "Maximum" fields. 
d. In the "Flood Protection" tab, select the "Other IP" check box; complete the "Alert", "Activate", and "Maximum" fields. 
e. In the "Flood Protection" tab, select the "UDP" check box; complete the "Alert", "Activate", and "Maximum" fields.
f. For each of the "Alert", "Activate", and "Maximum" fields, the appropriate values depends on the expected traffic of the system. 
5. Configure Reconnaissance Protection:
a. In the "Reconnaissance Protection" tab, select the "TCP Port Scan", "Host Sweep", and "UDP Port Scan" rows.
b. Select the action of Block IP.
c. The Interval and Threshold values can either remain as the default values or they can be changed based on the specific traffic conditions of the network.
6. Configure Packet Based Attack Protection settings:
a. Select the "Packet Based Attack Protection" tab and select the following at a minimum.
b. IP Drop tab: select the "Spoofed IP address", "Strict Source Routing", "Loose Source Routing", "Unknown", and "Malformed".
c. TCP Drop tab: select "Mismatched overlapping TCP segment" and "TCP Timestamp", and for the "Reject Non-SYN TCP" field, select "yes". For the "Asymmetric Path" field, select "bypass".
d. ICMP Drop tab: select the "ICMP Ping ID 0, ICMP Fragment", and "ICMP Large Packet(>1024)" check-boxes. The "Suppress ICMP TTL Expired Error" and "Suppress ICMP Frag Needed" check-boxes can remain unchecked unless this profile will be applied to an internal or DMZ.
e. IPv6 Drop tab: select the "Type 0 Routing Header", "IPv4 compatible address", "Anycast source address", "Needless fragment header", "MTU in ICMPv6 'Packet Too Big' less than 1280 bytes", "Hop-by-Hop extension", "Routing extension", "Destination extension", "Invalid IPv6 options in extension header", and "Non-zero reserved field" check-boxes.
f. In the "ICMPv6" tab, select the "ICMPv6 destination unreachable", "ICMPv6 packet too big", "ICMPv6 time exceeded", "ICMPv6 parameter problem", and "ICMPv6 redirect" check-boxes.
g. Click OK.
7. Apply the Zone Protection Profile to the internal zone and the DMZ:
a. Select Network >> Zones and select the internal zone.
b. In the "Zone" window, in the "Zone Protection Profile" window, select the configured Zone Protection Profile.
c. Click OK.
d. Select Network >> Zones and select the DMZ zone.
e. In the "Zone" window, in the "Zone Protection Profile" window, select the configured Zone Protection Profile.
f. Click OK.
8. Commit the changes.

To configure a DoS Protection policy:
1. Go to Objects >> Security Profiles >> DoS Protection.
2. Select "Add" to create a new profile.
3. In the "DoS Protection Profile" window, complete the required fields. For the "Type", select "Classified".
4. Configure Flood Protection by enabling each type of flood protection and configuring the following at a minimum:
a. SYN Flood tab: select "SYN Cookie" as the action.
b. UDP Flood tab: select "UDP Flood and complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
c. ICMP Flood tab: select "ICMP Flood" and complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
d. ICMPv6 Flood tab: select "ICMPv6 Flood" and complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
e. Other IP Flood tab: select "Other IP Flood" check box and complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
5. Configure Resources Protection in the Resources Protection tab with the following settings:
a. Select "Maximum Concurrent Sessions".
b. Complete the "Max Concurrent Sessions" field. If the DoS profile type is aggregate, this limit applies to the entire traffic hitting the DoS rule on which the DoS profile is applied.
c. Click OK and click Commit.
6. Create a DoS protection policy that specifies the criteria for matching the incoming traffic.
a. Go to Policies >> DoS Protection and select "Add" to create a new policy.
b. In the "DoS Rule" Window, complete the required fields.
c. In the "General" tab, complete the "Name" and "Description" fields.
d. In the "Source" tab, for "Zone", select the "External zone", and for "Source Address", select "Any".
e. In the "Destination" tab, "Zone", select "Internal zone", and for "Destination Address", select "Any".
f. In the "Option/Protection" tab, for "Service", select "Any", and for "Action", select "Protect".
g. Select the "Classified" check-box.
h. In the "Profile" field, select the configured DoS Protection profile for inbound traffic.
i. In the "Address" field, select destination-ip-only.
j. Click OK, and then Commit.)
  impact 0.7
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31095r768713_chk'
  tag severity: 'high'
  tag gid: 'V-228860'
  tag rid: 'SV-228860r767010_rule'
  tag stig_id: 'PANW-AG-000102'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-31072r768714_fix'
  tag 'documentable'
  tag legacy: ['SV-77091', 'V-62601']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
