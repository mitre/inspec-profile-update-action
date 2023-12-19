control 'SV-35202' do
  title 'The NFS server must not allow remote root access.'
  desc 'If the NFS server allows root access to local file systems from remote hosts, this access could be used to compromise the system.'
  desc 'check', 'Determine if the NFS server is sharing with the root access option.

# cat /etc/dfs/sharetab | grep "root="

If a share with the root option is found, this is a finding.'
  desc 'fix', 'Edit /etc/dfs/dfstab and remove the root= option for all shares. Re-share the file systems.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-38008r1_chk'
  tag severity: 'medium'
  tag gid: 'V-935'
  tag rid: 'SV-35202r1_rule'
  tag stig_id: 'GEN005880'
  tag gtitle: 'GEN005880'
  tag fix_id: 'F-33243r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Manager', 'Information Assurance Officer']
  tag ia_controls: 'EBRP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
