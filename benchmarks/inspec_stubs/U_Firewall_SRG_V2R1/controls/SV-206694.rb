control 'SV-206694' do
  title 'The firewall must deny network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception).'
  desc 'To prevent malicious or accidental leakage of traffic, organizations must implement a deny-by-default security posture at the network perimeter. Such rulesets prevent many malicious exploits or accidental leakage by restricting the traffic to only known sources and only those ports, protocols, or services that are permitted and operationally necessary.

As a managed boundary interface, the firewall must block all inbound and outbound network traffic unless a filter is installed to explicitly allow it. The allow filters must comply with the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and Vulnerability Assessment (VA).'
  desc 'check', 'Determine the default security policies on the firewall for traffic from one zone to another zone (inter-zone). 

The default policy must be a "Deny" policy that blocks all inter-zone traffic by default. Ensure no policy that circumvents the default "Deny" inter-zone policy is allowed. Traffic through the firewall is filtered so that only the specific traffic that is approved and registered in the PPSM CAL and VAs for the enclave. Verify rules or access control statements containing "any" for either the host, destination, protocol, or port are not used.

If the firewall does not deny all network communications traffic by default and allow network communications traffic by exception (i.e., deny all, permit by exception), this is a finding.'
  desc 'fix', 'Configure the firewall with a "Deny" inter-zone policy which, by default, blocks traffic between zones and allows network communications traffic by exception (i.e., deny all, permit by exception) in accordance with PPSM CAL and VAs for the enclave.'
  impact 0.7
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6951r297861_chk'
  tag severity: 'high'
  tag gid: 'V-206694'
  tag rid: 'SV-206694r604133_rule'
  tag stig_id: 'SRG-NET-000202-FW-000039'
  tag gtitle: 'SRG-NET-000202'
  tag fix_id: 'F-6951r297862_fix'
  tag 'documentable'
  tag legacy: ['SV-94121', 'V-79415']
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
