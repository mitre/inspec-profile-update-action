control 'SV-46123' do
  title 'The Network File System (NFS) anonymous UID and GID must be configured to values without permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user.  The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'check', %q(Check if the nfs-kernel-server package is installed.  It contains the exportfs command as well as the nfsserver process itself.
# rpm –q nfs-kernel-server

If the package is not installed, this check does not apply. If it is installed, check if the 'anonuid' and 'anongid' options are set correctly for exported file systems.
List exported filesystems:
# exportfs -v 

Each of the exported file systems should include an entry for the 'anonuid=' and 'anongid=' options set to "-1" or an equivalent (60001, 65534, or 65535). If appropriate values for 'anonuid' or 'anongid' are not set, this is a finding.)
  desc 'fix', 'Edit "/etc/exports" and set the "anonuid=-1" and "anongid=-1" options for exports lacking it. Re-export the filesystems.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43380r1_chk'
  tag severity: 'medium'
  tag gid: 'V-932'
  tag rid: 'SV-46123r1_rule'
  tag stig_id: 'GEN005820'
  tag gtitle: 'GEN005820'
  tag fix_id: 'F-39464r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000062']
  tag nist: ['AC-14 (1)']
end
