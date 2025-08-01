control 'SV-37854' do
  title 'The Network File System (NFS) anonymous UID and GID must be configured to values without permissions.'
  desc 'When an NFS server is configured to deny remote root access, a selected UID and GID are used to handle requests from the remote root user.  The UID and GID should be chosen from the system to provide the appropriate level of non-privileged access.'
  desc 'fix', 'Edit "/etc/exports" and set the "anonuid=-1" and "anongid=-1" options for exports lacking it. Re-export the filesystems.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-932'
  tag rid: 'SV-37854r1_rule'
  tag stig_id: 'GEN005820'
  tag gtitle: 'GEN005820'
  tag fix_id: 'F-32316r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000062']
  tag nist: ['AC-14 (1)']
end
