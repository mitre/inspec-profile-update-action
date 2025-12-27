control 'SV-207699' do
  title 'The Palo Alto Networks security platform must block malicious ICMP packets.'
  desc 'Internet Control Message Protocol (ICMP) messages are used to provide feedback about problems in the network. These messages are sent back to the sender to support diagnostics.  However, ICMP can be misused to provide a covert channel. ICMP tunneling is when an attacker injects arbitrary data into an echo packet and sends to a remote computer. The remote computer injects an answer into another ICMP packet and sends it back.  The creates a covert channel where an attacker can hide commands sent to a compromised host or a compromised host can exfiltrate data.'
  desc 'check', 'Ask the Administrator which Security Policy blocks traceroutes and ICMP probes.
Go to Policies >> Security
View the identified Security Policy.
 
If the  "Source Zone" field is not external and the "Source Address" field is not any, this is a finding.

If the "Destination Zone" fields do not include the internal and DMZ zones and the "Destination Address" field is not "any", this is a finding.
Note: the exact number and name of zones is specific to the network.

If the "Application" fields do not include "icmp", "ipv6-icmp", and "traceroute", this is a finding.

If the "Actions" field does not show "Deny" as the resulting action, this is a finding.'
  desc 'fix', 'To configure the security policy:
Go to Policies >> Security
Select "Add".
In the "Security Policy Rule" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.
For the "Source Zone" field, select "external". 
For the "Source Address" field, select "any".
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields. 
For the "Destination Zone" field, select the internal and DMZ zones.
Note: the exact number and name of zones is specific to the network.

For the "Destination Address" field, select "any".
In the "Applications" tab, select "icmp", "ipv6-icmp", "traceroute".
In the "Actions" tab, select "Deny" as the resulting action.  Select the required Log Setting and Profile Settings as necessary.
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7953r358430_chk'
  tag severity: 'medium'
  tag gid: 'V-207699'
  tag rid: 'SV-207699r557390_rule'
  tag stig_id: 'PANW-IP-000031'
  tag gtitle: 'SRG-NET-000273-IDPS-00204'
  tag fix_id: 'F-7953r358431_fix'
  tag 'documentable'
  tag legacy: ['SV-77159', 'V-62669']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
