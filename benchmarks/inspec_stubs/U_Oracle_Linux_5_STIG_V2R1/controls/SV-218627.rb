control 'SV-218627' do
  title 'The Network File System (NFS) export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', '# ls -lL /etc/exports
If the file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', '# chmod 0644 /etc/exports'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20102r562861_chk'
  tag severity: 'low'
  tag gid: 'V-218627'
  tag rid: 'SV-218627r603259_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20100r562862_fix'
  tag 'documentable'
  tag legacy: ['V-929', 'SV-64199']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
