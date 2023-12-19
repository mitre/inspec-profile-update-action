control 'SV-227012' do
  title 'The NFS anonymous UID and GID must be configured to values that have no permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user.  The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'check', "Check if the anon option is set correctly for exported file systems.

List exported file systems.
# exportfs -v
OR
# more /etc/dfs/sharetab

Each of the exported file systems should include an entry for the 'anon=' option set to -1 or an equivalent (60001, 60002, 65534, or 65535). If an appropriate 'anon=' setting is not present for an exported file system, this is a finding."
  desc 'fix', 'Edit /etc/dfs/dfstab and add the "anon=-1" option for exports lacking it.  Re-export the filesystems.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29174r485381_chk'
  tag severity: 'medium'
  tag gid: 'V-227012'
  tag rid: 'SV-227012r603265_rule'
  tag stig_id: 'GEN005820'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-29162r485382_fix'
  tag 'documentable'
  tag legacy: ['SV-40304', 'V-932']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
