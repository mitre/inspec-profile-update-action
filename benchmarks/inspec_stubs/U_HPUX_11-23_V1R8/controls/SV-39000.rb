control 'SV-39000' do
  title 'The NFS export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', %q(# echo `ls -lL /etc/exports` | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | cut -f 1,1 -d " "

If the file has a mode more permissive than 0644, this is a finding.)
  desc 'fix', '# chmod 0644 /etc/exports'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35028r1_chk'
  tag severity: 'low'
  tag gid: 'V-929'
  tag rid: 'SV-39000r1_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'GEN005760'
  tag fix_id: 'F-30320r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECLP-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
