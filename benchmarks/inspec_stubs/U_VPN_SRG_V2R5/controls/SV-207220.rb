control 'SV-207220' do
  title 'The VPN Gateway must be configured to route sessions to an IDPS for inspection.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated, capabilities increase risk and makes remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Verify the VPN Gateway routes sessions to an IDPS for inspection.

If the VPN Gateway is not  configured to route sessions to an IDPS for inspection, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to route sessions to an IDPS for inspection.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7480r378281_chk'
  tag severity: 'medium'
  tag gid: 'V-207220'
  tag rid: 'SV-207220r608988_rule'
  tag stig_id: 'SRG-NET-000205-VPN-000710'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7480r378282_fix'
  tag 'documentable'
  tag legacy: ['SV-106257', 'V-97119']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
