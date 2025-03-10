control 'SV-214678' do
  title 'If IDPS inspection is performed separately from the Juniper SRX Services Gateway VPN device, the VPN must route sessions to an IDPS for inspection.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated, capabilities increase risk and makes remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. 

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', "Inspect the Juniper SRX configuration or the site's architecture drawings to verify all inbound VPN traffic is routed to the site's intrusion detection system.

If all inbound VPN traffic is not inspected by the site's IDPS prior to being routed to its destination, this is a finding."
  desc 'fix', 'Configure the Juniper SRX to route traffic to the port attached to intrusion detection system or configure to route all inbound traffic to the sites intrusion detection system using the IP address of the IPS/IDS.'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15879r864167_chk'
  tag severity: 'medium'
  tag gid: 'V-214678'
  tag rid: 'SV-214678r864169_rule'
  tag stig_id: 'JUSX-VN-000011'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-15877r864168_fix'
  tag 'documentable'
  tag legacy: ['V-66653', 'SV-81143']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
