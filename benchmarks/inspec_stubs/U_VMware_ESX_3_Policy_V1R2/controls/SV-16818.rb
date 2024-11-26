control 'SV-16818' do
  title 'VirtualCenter Server groups are not reviewed monthly'
  desc 'Reviewing the VirtualCenter groups will ensure that no unauthorized users have been granted access to objects.'
  desc 'check', 'Ask the IAO/SA how often the following groups are reviewed on the VirtualCenter Server:

Windows Administrators group,
Database Administrators,
Virtual Machine Administrators,
Resource Pool Administrators,
ESX Administrators,
Virtual Machine Power Users, and
All Custom Roles.

If these groups are not reviewed at least monthly, this is a finding.'
  desc 'fix', 'Review the VirtualCenter groups monthly.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15877'
  tag rid: 'SV-16818r1_rule'
  tag stig_id: 'ESX0780'
  tag gtitle: 'VirtualCenter Server groups are not reviewed'
  tag fix_id: 'F-15837r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECAT-1, ECAT-2'
end
