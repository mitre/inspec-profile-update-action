control 'SV-207703' do
  title 'The Palo Alto Networks security platform must protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis (traffic thresholds).'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself.'
  desc 'check', 'Go to Objects >> Security Profiles >> DoS Protection
If there are no DoS Protection Profiles configured, this is a finding.

Go to Policies >> DoS Protection
If there are no DoS Protection Policies, this is a finding.

There may be more than one configured DoS Protection Policy; ask the Administrator which DoS Protection Policy is intended to protect internal networks and DMZ networks from externally-originated DoS attacks.
  
If there is no such DoS Protection Policy, this is a finding.

If the DoS Protection Policy has no DoS Protection Profile, this is a finding.'
  desc 'fix', 'Go to Objects >> Security Profiles >> DoS Protection
Select "Add" to create a new profile.
In the "DoS Protection Profile" window, complete the required fields.
For the "Type", select "Classified".
In the "Flood Protection" tab, "Syn Flood" tab, select the "Syn Flood" check box and select "SYN Cookie".   
In the "Flood Protection" tab, "UDP Flood" tab, select the "UDP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMP Flood" tab, select the "ICMP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.
In the "Flood Protection" tab, "ICMPv6 Flood" tab, select the "ICMPv6 Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields.  
In the "Flood Protection" tab, "Other IP Flood" tab, select the "Other IP Flood" check box; complete the "Alarm Rate", "Activate Rate", "Max Rate", and "Block Duration" fields. 
In the "Resources Protection" tab, select the "Maximum Concurrent Sessions" check box.
In the "Resources Protection" tab, complete the "Max Concurrent Sessions" field.  If the DoS profile type is aggregate, this limit applies to the entire traffic hitting the DoS rule on which the DoS profile is applied. If the DoS profile type is classified, this limit applies to the entire traffic on a classified basis (source IP, destination IP or source-and-destination IP) hitting the DoS rule on which the DoS profile is applied.
Select "OK".

Go to Policies >> DoS Protection
Select "Add" to create a new policy.
In the "DoS Rule" Window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, for "Zone", select the "External zone, for Source Address", select "Any".
In the "Destination" tab,  "Zone", select "Internal zone, for Destination Address", select "Any".
In the "Option/Protection" tab, 
For "Service", select "Any".
For "Action", select "Protect".
Select the "Classified" check box.
In the "Profile" field, select the configured DoS Protection profile for inbound traffic.
In the "Address" field, select "destination-ip-only".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7957r358442_chk'
  tag severity: 'medium'
  tag gid: 'V-207703'
  tag rid: 'SV-207703r557390_rule'
  tag stig_id: 'PANW-IP-000041'
  tag gtitle: 'SRG-NET-000362-IDPS-00196'
  tag fix_id: 'F-7957r358443_fix'
  tag 'documentable'
  tag legacy: ['V-62677', 'SV-77167']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
