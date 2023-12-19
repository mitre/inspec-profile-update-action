control 'SV-16810' do
  title 'Unauthorized users have access to the VirtualCenter virtual machine.'
  desc 'Virtual machines may be accessed by anyone with the proper permissions. If the VirtualCenter virtual machine is accessed by a normal virtual machine user, specific settings in the virtual infrastructure may be changed or modified.  Modifications may include permissions, object groupings, installing malicious software, etc. To mitigate this, access to the VirtualCenter virtual machine will be restricted to only authorized users.'
  desc 'check', '1. Request a copy of the authorized VirtualCenter administrator user documentation.  If no documentation exists, this is a finding.
2. Log into the VI Client as a user with Administrator privileges.  Work with the system administrator to access the system with these privileges.
3. In the Inventory panel on the left, select the VirtualCenter virtual machine.
4. Click the Permissions tab.
5. Review the permissions and verify that they match the documentation provided. If there is a discrepancy, this is a finding.'
  desc 'fix', 'Restrict access to the VirtualCenter virtual machine to only authorized users.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16226r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15869'
  tag rid: 'SV-16810r1_rule'
  tag stig_id: 'ESX0700'
  tag gtitle: 'Unauthorized users have access to VirtualCenter vm'
  tag fix_id: 'F-15829r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
