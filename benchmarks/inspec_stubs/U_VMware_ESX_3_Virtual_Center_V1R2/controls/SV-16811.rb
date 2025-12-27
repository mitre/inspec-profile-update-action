control 'SV-16811' do
  title 'No dedicated VirtualCenter administrator created within the Windows Administrator Group on the Windows Server for managing the VirtualCenter environment.'
  desc 'By default, the local administrator or domain administrator is allowed to log on to VirtualCenter. These administrators are allowed since VirtualCenter requires a user with local administrator privileges to run. To limit the local administrative access, a dedicated VirtualCenter account will be created. This VirtualCenter account is an ordinary user that is a member of the local administrators group. This configuration avoids automatically giving administrative access to domain administrators, who typically belong to the local administrators group. This also provides a way of getting into VirtualCenter when the domain controller is down, because the local VirtualCenter administrator account does not require remote authentication.'
  desc 'check', '1. On the VirtualCenter Server, go to Start>Administrative Tools>Computer Management>Local Users and Groups>Groups
2. Open the Administrators group.
3. Verify that a VirtualCenter administrator is listed.  Work with the system administrator to identify the user.

If no VirtualCenter administrator is listed, this is a finding.'
  desc 'fix', 'Create a VirtualCenter administrator user in the Windows Administrator Group.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15870'
  tag rid: 'SV-16811r1_rule'
  tag stig_id: 'ESX0710'
  tag gtitle: 'No dedicated VirtualCenter administrator'
  tag fix_id: 'F-15830r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECCD-1, ECCD-2'
end
