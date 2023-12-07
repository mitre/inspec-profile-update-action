control 'SV-37859' do
  title 'The Network File System (NFS) server must not allow remote root access.'
  desc 'If the NFS server allows root access to local file systems from remote hosts, this access could be used to compromise the system.'
  desc 'fix', 'Edit the "/etc/exports" file and add "root_squash" (or "all_squash") and remove "no_root_squash".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-935'
  tag rid: 'SV-37859r1_rule'
  tag stig_id: 'GEN005880'
  tag gtitle: 'GEN005880'
  tag fix_id: 'F-32333r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'EBRP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
