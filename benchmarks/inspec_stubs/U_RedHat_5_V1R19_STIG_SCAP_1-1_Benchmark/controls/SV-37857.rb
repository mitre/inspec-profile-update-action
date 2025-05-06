control 'SV-37857' do
  title 'The Network File System (NFS) server must be configured to restrict file system access to local hosts.'
  desc "The NFS access option limits user access to the specified level. This assists in protecting exported file systems.  If access is not restricted, unauthorized hosts may be able to access the system's NFS exports."
  desc 'fix', 'Edit /etc/exports and add ro and/or rw options (as appropriate) specifying a list of hosts or networks which are permitted access. Re-export the file systems.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-933'
  tag rid: 'SV-37857r1_rule'
  tag stig_id: 'GEN005840'
  tag gtitle: 'GEN005840'
  tag fix_id: 'F-32328r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
