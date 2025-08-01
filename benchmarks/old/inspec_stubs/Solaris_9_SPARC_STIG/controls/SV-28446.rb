control 'SV-28446' do
  title 'The NFS export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'fix', 'Change the permissions of the dfstab file to 664 or less permissive.

# chmod 0644 /etc/dfs/dfstab'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-929'
  tag rid: 'SV-28446r1_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'GEN005760'
  tag fix_id: 'F-25759r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECLP-1, ECCD-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
