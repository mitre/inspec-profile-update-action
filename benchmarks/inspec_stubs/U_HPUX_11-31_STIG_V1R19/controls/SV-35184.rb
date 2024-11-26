control 'SV-35184' do
  title 'The Network File System (NFS) share configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS share configuration file could allow unauthorized modification of the file, which could result in Denial-of-Service to authorized NFS shares and the creation of additional unauthorized shares.'
  desc 'check', %q(# echo `ls -lL /etc/dfs/dfstab` | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | cut -f 1,1 -d " "

If the file has a mode more permissive than 0644, this is a finding.)
  desc 'fix', '# chmod 0644 /etc/dfs/dfstab'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-37992r1_chk'
  tag severity: 'low'
  tag gid: 'V-929'
  tag rid: 'SV-35184r1_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'GEN005760'
  tag fix_id: 'F-33232r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2, ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
