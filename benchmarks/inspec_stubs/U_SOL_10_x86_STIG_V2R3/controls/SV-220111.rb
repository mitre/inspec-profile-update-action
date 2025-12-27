control 'SV-220111' do
  title 'The NFS server must be configured to restrict file system access to local hosts.'
  desc "The NFS access option limits user access to the specified level. This assists in protecting exported file systems.  If access is not restricted, unauthorized hosts may be able to access the system's NFS exports."
  desc 'check', 'Check the permissions on exported NFS file systems.

Procedure:
# exportfs -v
OR
# more /etc/dfs/sharetab

If the exported file systems do not contain the rw or ro options specifying a list of hosts or networks, this is a finding.'
  desc 'fix', 'Edit /etc/dfs/dfstab and add ro and/or rw options (as appropriate) specifying a list of hosts or networks which are permitted access.  Re-export the file systems.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21820r490171_chk'
  tag severity: 'medium'
  tag gid: 'V-220111'
  tag rid: 'SV-220111r603266_rule'
  tag stig_id: 'GEN005840'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21819r490172_fix'
  tag 'documentable'
  tag legacy: ['V-933', 'SV-40305']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
