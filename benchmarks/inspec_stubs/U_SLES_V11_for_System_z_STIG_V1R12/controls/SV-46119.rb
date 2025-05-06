control 'SV-46119' do
  title 'The Network File System (NFS) export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', '# ls -lL /etc/exports
If the file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', '# chmod 0644 /etc/exports'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43376r1_chk'
  tag severity: 'low'
  tag gid: 'V-929'
  tag rid: 'SV-46119r1_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'GEN005760'
  tag fix_id: 'F-39460r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
