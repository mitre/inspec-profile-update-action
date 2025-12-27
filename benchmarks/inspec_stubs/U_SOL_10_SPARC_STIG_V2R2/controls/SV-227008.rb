control 'SV-227008' do
  title 'The NFS export configuration file must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', '# ls -lL /etc/dfs/dfstab 
 If the file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions of the dfstab file to 664 or less permissive.

# chmod 0644 /etc/dfs/dfstab'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29170r485369_chk'
  tag severity: 'low'
  tag gid: 'V-227008'
  tag rid: 'SV-227008r603265_rule'
  tag stig_id: 'GEN005760'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29158r485370_fix'
  tag 'documentable'
  tag legacy: ['V-929', 'SV-28446']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
