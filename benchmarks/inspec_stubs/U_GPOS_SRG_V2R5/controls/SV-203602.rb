control 'SV-203602' do
  title 'The operating system must monitor remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify the operating system monitors remote access methods. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to monitor remote access methods.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3727r557062_chk'
  tag severity: 'medium'
  tag gid: 'V-203602'
  tag rid: 'SV-203602r557064_rule'
  tag stig_id: 'SRG-OS-000032-GPOS-00013'
  tag gtitle: 'SRG-OS-000032'
  tag fix_id: 'F-3727r557063_fix'
  tag 'documentable'
  tag legacy: ['V-56639', 'SV-70899']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
