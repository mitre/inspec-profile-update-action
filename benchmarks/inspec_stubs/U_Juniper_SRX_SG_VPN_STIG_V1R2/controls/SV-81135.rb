control 'SV-81135' do
  title 'The Juniper SRX Services Gateway VPN device also fulfills the role of IDPS in the architecture, the device must inspect the VPN traffic in compliance with DoD IDPS requirements.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated, capabilities increase risk and makes remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. 

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Obtain documentation from the site representative that the Juniper SRX is configured in compliance with the Juniper SRX Services Gateway IDPS STIG.

If the device has not been configured to comply with DoD IDPS requirements, this is a finding.'
  desc 'fix', 'Perform a security review using the Juniper SRX Services Gateway IDPS STIG.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67271r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66645'
  tag rid: 'SV-81135r1_rule'
  tag stig_id: 'JUSX-VN-000004'
  tag gtitle: 'SRG-NET-000061'
  tag fix_id: 'F-72721r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
