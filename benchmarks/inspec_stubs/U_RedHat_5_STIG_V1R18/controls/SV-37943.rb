control 'SV-37943' do
  title 'The Network File System (NFS) export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', '# ls -lL /etc/exports
If the file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', '# chmod 0644 /etc/exports'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37223r1_chk'
  tag severity: 'low'
  tag gid: 'V-929'
  tag rid: 'SV-37943r1_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'GEN005760'
  tag fix_id: 'F-32434r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2, ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
