control 'SV-46124' do
  title 'The Network File System (NFS) server must be configured to restrict file system access to local hosts.'
  desc "The NFS access option limits user access to the specified level. This assists in protecting exported file systems.  If access is not restricted, unauthorized hosts may be able to access the system's NFS exports."
  desc 'check', 'Check if the nfs-kernel-server package is installed.  It contains the exportfs command as well as the nfsserver process itself.
# rpm –q nfs-kernel-server

If the package is not installed, this check does not apply.  If it is installed, check the permissions on exported NFS file systems.

Procedure:
# exportfs -v

If the exported file systems do not contain the ‘rw’ or ‘ro’ options specifying a list of hosts or networks, this is a finding.'
  desc 'fix', 'Edit /etc/exports and add ro and/or rw options (as appropriate) specifying a list of hosts or networks which are permitted access. Re-export the file systems.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43382r1_chk'
  tag severity: 'medium'
  tag gid: 'V-933'
  tag rid: 'SV-46124r1_rule'
  tag stig_id: 'GEN005840'
  tag gtitle: 'GEN005840'
  tag fix_id: 'F-39466r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
