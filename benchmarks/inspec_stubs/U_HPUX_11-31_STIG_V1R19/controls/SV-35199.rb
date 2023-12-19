control 'SV-35199' do
  title 'The Network File System (NFS) anonymous UID and GID must be configured to values that have no permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user.  The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'check', "Check if the 'anon' option is set correctly for shared file systems.
# cat /etc/dfs/dfstab

Each of the shared file systems should include an entry for the 'anon=' option set to -1 or an equivalent (60001, 65534, or 65535). If an appropriate 'anon=' setting is not present for a shared file system, this is a finding."
  desc 'fix', 'Edit /etc/dfs/sharetab and set the anon=-1 option for shares without it. Re-export the file systems.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-38003r1_chk'
  tag severity: 'medium'
  tag gid: 'V-932'
  tag rid: 'SV-35199r1_rule'
  tag stig_id: 'GEN005820'
  tag gtitle: 'GEN005820'
  tag fix_id: 'F-33237r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000062']
  tag nist: ['AC-14 (1)']
end
