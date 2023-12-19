control 'SV-206676' do
  title 'The firewall that filters traffic from the VPN access points must be configured with organization-defined filtering rules that apply to the monitoring of remote access traffic.'
  desc 'Remote access devices (such as those providing remote access to network devices and information systems) that lack automated capabilities increase risk and make remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Review the firewall configuration statements used to create a group policy with filtering rules for remote clients accessing the network using a VPN.

Verify both ingress and egress traffic on this interface is subject to the remote access policy and filtering rules required by the organization. 

If the firewall is used to filter traffic from the VPN access points but is not configured with filtering rules that apply to the monitoring of remote access traffic, this is a finding.'
  desc 'fix', 'Configure a group policy for remote clients and apply to the interface that is connected to allow ingress and egress to the VPN access points.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6933r297807_chk'
  tag severity: 'medium'
  tag gid: 'V-206676'
  tag rid: 'SV-206676r604133_rule'
  tag stig_id: 'SRG-NET-000061-FW-000001'
  tag gtitle: 'SRG-NET-000061'
  tag fix_id: 'F-6933r297808_fix'
  tag 'documentable'
  tag legacy: ['SV-94129', 'V-79423']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
