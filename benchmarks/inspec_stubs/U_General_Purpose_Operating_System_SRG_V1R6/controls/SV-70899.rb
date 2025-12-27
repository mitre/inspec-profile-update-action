control 'SV-70899' do
  title 'The operating system must monitor remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify the operating system monitors remote access methods. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to monitor remote access methods.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57209r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56639'
  tag rid: 'SV-70899r1_rule'
  tag stig_id: 'SRG-OS-000032-GPOS-00013'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-61535r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
