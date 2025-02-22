control 'SV-16817' do
  title 'Users in the VirtualCenter Server Windows Administrators group are not documented.'
  desc 'Users who are members of the Windows administrators group on the VirtualCenter server are granted the same access rights as any user assigned to the VirtualCenter administrator role. These users need to be documented to ensure only authorized users are members of this group.'
  desc 'check', 'Request a copy of the document specifying users assigned to the Windows Administrators group on the VirtualCenter Server.  If no documentation exists, this is a finding. Compare the documented users to those listed in the group on the server.   If any discrepancies exist, this is a finding.'
  desc 'fix', 'Document all users in the Windows Administrators group.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16234r1_chk'
  tag severity: 'low'
  tag gid: 'V-15876'
  tag rid: 'SV-16817r1_rule'
  tag stig_id: 'ESX0770'
  tag gtitle: 'Users are not documented correctly'
  tag fix_id: 'F-15836r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
