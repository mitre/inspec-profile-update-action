control 'SV-207692' do
  title 'The Palo Alto Networks security platform must have a DoS Protection Profile for outbound traffic applied to a policy for traffic originating from the internal zone going to the external zone.'
  desc 'The Palo Alto Networks security platform must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave.

Installation of Palo Alto Networks security platform detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

To comply with this requirement, the Palo Alto Networks security platform must inspect outbound traffic for indications of known and unknown DoS attacks. Sensor log capacity management along with techniques which prevent the logging of redundant information during an attack also guard against DoS attacks. This requirement is used in conjunction with other requirements which require configuration of security policies, signatures, rules, and anomaly detection techniques and are applicable to both inbound and outbound traffic.'
  desc 'check', 'Go to Objects >> Security Profiles >> DoS Protection
If there are no DoS Protection Profiles configured, this is a finding.

There may be more than one configured DoS Protection Profile; ask the Administrator which DoS Protection Profile is intended to protect outside networks from internally-originated DoS attacks.
If there is no such DoS Protection Profile, this is a finding.'
  desc 'fix', 'Go to Objects >> Security Profiles >> DoS Protection
Select "Add" to create a new profile.
In the "DoS Protection Profile" window, complete the required fields.
For the Type, select "Classified".
In the "Flood Protection" tab, "Syn Flood" tab, select the "Syn Flood" check box and select either "Random Early Drop" (preferred in this case) or "SYN Cookie".   
In the "Flood Protection" tab, "UDP Flood" tab, select the "UDP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMP Flood" tab, select the "ICMP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMPv6 Flood" tab, select the "ICMPv6 Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.  
In the "Flood Protection" tab, "Other IP Flood" tab, select the "Other IP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
In the "Resources Protection" tab, leave the "Maximum Concurrent Sessions" check box unselected.
Select "OK".

Go to Policies >> DoS Protection
Select "Add" to create a new policy.
In the "DoS Rule" Window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, for "Zone", select the "Internal zone", for "Source Address", select "Any".
In the "Destination" tab,  "Zone", select "External zone", for "Destination Address", select "Any".
In the "Option/Protection" tab:
For "Service", select "Any".
For "Action", select "Protect".
Select the "Classified" check box.
In the "Profile" field, select the configured DoS Protection profile for outbound traffic.
In the "Address field", select "source-ip-only".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7946r358409_chk'
  tag severity: 'medium'
  tag gid: 'V-207692'
  tag rid: 'SV-207692r557390_rule'
  tag stig_id: 'PANW-IP-000018'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-7946r358410_fix'
  tag 'documentable'
  tag legacy: ['SV-77145', 'V-62655']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
