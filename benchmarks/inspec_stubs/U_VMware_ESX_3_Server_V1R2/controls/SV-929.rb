control 'SV-929' do
  title 'The NFS export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial-of-Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', 'Check the ownership of the NFS export configuration file.  If the file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the NFS export configuration file to 0644.
# chmod 0644 <NFS export file>'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-856r2_chk'
  tag severity: 'low'
  tag gid: 'V-929'
  tag rid: 'SV-929r2_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'GEN005760'
  tag fix_id: 'F-1083r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2, ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
