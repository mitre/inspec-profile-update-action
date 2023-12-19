control 'SV-228842' do
  title 'The Palo Alto Networks security platform must protect against the use of internal systems from launching Denial of Service (DoS) attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

It is important to set the Flood Protection parameters that are suitable for the enclave or system.  The Administrator should characterize the traffic regularly (perform a traffic baseline) and tune these parameters based on that information.'
  desc 'check', 'Ask the Administrator if the device is using a Zone-Based Protection policy or a DoS Protection policy to protect against DoS attacks originating from the enclave.
If it is using a DoS Protection policy, perform the following;
Go to Objects >> Security Profiles >> DoS Protection
If there are no DoS Protection Profiles configured, this is a finding.
There may be more than one configured DoS Protection Profile; ask the Administrator which DoS Protection Profile is intended to protect outside networks from internally-originated DoS attacks.
If there is no such DoS Protection Profile, this is a finding.

If it is using a Zone-Based Protection policy, perform the following;
Go to Network >> Network Profiles >> Zone Protection
If there are no Zone Protection Profiles configured, this is a finding.
There may be more than one configured Zone Protection Profile; ask the Administrator which  Zone Protection Profile is intended to protect outside networks from internally-originated DoS attacks.
If there is no such Zone Protection Profile, this is a finding.
Go to Network >> Zones
If the Zone Protection Profile column for the External zone is blank, this is a finding.
If it lists an incorrect Zone Protection Profile, this is also a finding.'
  desc 'fix', %q(Configure either a Zone-Based Protection policy or a DoS Protection policy to protect against DoS attacks originating from the enclave.

To configure a DoS Protection policy, perform the following:
Go to Objects >> Security Profiles >> DoS Protection
Select "Add" to create a new profile.
In the "DoS Protection Profile" window, complete the required fields.
For the "Type", select "Classified".
In the "Flood Protection" tab, "SYN Flood" sub-tab, select the "SYN Flood" check box and select either "Random Early Drop" (preferred in this case) or "SYN Cookie"; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "UDP Flood" sub-tab, select the "UDP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMP Flood" sub-tab, select the "ICMP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMPv6 Flood" sub-tab, select the "ICMPv6 Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
In the "Flood Protection" tab, "Other IP Flood" sub-tab, select the "Other IP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
In the "Resources Protection" tab, leave the "Maximum Concurrent Sessions" check box unselected.
Select "OK".

Go to Policies >> DoS Protection
Select "Add" to create a new policy.
In the "DoS Rule" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, for "Zone", select the "Internal" zone, for "Source Address", select "Any".
In the "Destination" tab, "Zone", select "External" zone, for "Destination Address", select "Any".
In the "Option/Protection" tab, 
For "Service", select "Any".
For "Action", select "Protect".
Select the "Classified" check box.
In the "Profile" field, select the configured DoS Protection profile for outbound traffic.
In the "Address" field, select source-ip-only.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.

To configure a Zone-Based Protection policy, perform the following:
Go to Network >> Network Profiles >> Zone Protection
Select "Add".
In the "Zone Protection Profile" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Flood Protection" tab, select the "SYN" check box, in the "Action" field, select either "Random Early Drop" (preferred in this case) or "SYN Cookie"; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "ICMP" check box; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "ICMPv6" check box; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "Other IP" check box; complete the "Alert", "Activate", and "Maximum" fields. 
In the "Flood Protection" tab, select the "UDP" check box; complete the "Alert", "Activate", and "Maximum" fields.
For each of the "Alert", "Activate", and "Maximum" fields, the appropriate values depend on the expected traffic of the system. 
In the "Reconnaissance Protection" tab, select the "TCP Port Scan", "Host Sweep", and "UDP Port Scan" rows. In the "Action" field, select "Block". The "Interval" and "Threshold" values can either remain as the default values or they can be changed based on the specific traffic conditions of the network (preferred).

In the "Packet Based Attack Protection" tab:
"TCP/IP Drop" sub-tab, select the "Spoofed IP address", and "Mismatched overlapping TCP segment" check boxes.
In the "IP Option Drop" section, select the "Strict Source Routing", "Loose Source Routing", "Timestamp", "Unknown", and "Malformed" check boxes. 
The "Record Route", "Security", and "Stream ID" check boxes can remain unchecked.
For the "Reject Non-SYN TCP" field, select "yes".
For the "Asymmetric Path" field, select "bypass".

"ICMP Drop" sub-tab, select the "ICMP Ping ID 0", "ICMP Fragment", "ICMP Large Packet(>1024)" check boxes.
The "Discard ICMP embedded with error message", "Suppress ICMP TTL Expired Error", and "Suppress ICMP Frag Needed" boxes can remain unchecked.
Since this requirement is specifically to prevent internal systems from launching DoS attacks against other networks or endpoints, select the following from the "ICMP Drop" sub-tab: "ICMP Ping ID 0", "ICMP Fragment", "ICMP Large Packet(>1024)", "Suppress ICMP TTL Expired Error", "Suppress ICMP Frag Needed".
"IPv6 Drop" sub-tab, select the "Type 0 Routing Header", "IPv4 compatible address", "Anycast source address", "Needless fragment header", "MTU in ICMPv6 'Packet Too Big' less than 1280 bytes", "Hop-by-Hop extension", "Routing extension", "Destination extension", "Invalid IPv6 options in extension header", and "Non-zero reserved field" check boxes.
"ICMPv6" sub-tab, select the "ICMPv6 destination unreachable", "ICMPv6 packet too big", "ICMPv6 time exceeded", "ICMPv6 parameter problem", and "ICMPv6 redirect" check boxes.
Select "OK".

Apply the Zone Protection Profile to the exterior zone:
Go to Network >> Zones
Select the exterior zone.
In the "Zone" window, in the "Zone Protection Profile" window, select the configured Zone Protection Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31077r513821_chk'
  tag severity: 'medium'
  tag gid: 'V-228842'
  tag rid: 'SV-228842r557387_rule'
  tag stig_id: 'PANW-AG-000047'
  tag gtitle: 'SRG-NET-000192-ALG-000121'
  tag fix_id: 'F-31054r513822_fix'
  tag 'documentable'
  tag legacy: ['V-62567', 'SV-77057']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
