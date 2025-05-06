control 'SV-35201' do
  title 'The Network File System (NFS) server must be configured to restrict file system access to local hosts.'
  desc "The NFS access option limits user access to the specified level. This assists in protecting shared file systems.  If access is not restricted, unauthorized hosts may be able to access the system's NFS shares."
  desc 'check', 'Check the permissions on shared NFS file systems.

Procedure:
# cat /etc/dfs/sharetab

If the shared file systems do not contain the "rw" or "ro" options that specify a list of hosts or networks, this is a finding.'
  desc 'fix', 'Edit /etc/dfs/dfstab and add ro and/or rw options (as appropriate) that specify a list of hosts or networks which are permitted access. Re-share the file systems via the following commands:
# unshare <the file system entry that was modified>
# share <the file system entry that was modified>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-38005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-933'
  tag rid: 'SV-35201r1_rule'
  tag stig_id: 'GEN005840'
  tag gtitle: 'GEN005840'
  tag fix_id: 'F-33239r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
