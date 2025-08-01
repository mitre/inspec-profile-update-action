control 'SV-227009' do
  title 'The NFS exports configuration file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', 'Check the group ownership of the NFS export configuration file.
# ls -lL /etc/dfs/dfstab
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/dfs/dfstab'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29171r485372_chk'
  tag severity: 'low'
  tag gid: 'V-227009'
  tag rid: 'SV-227009r603265_rule'
  tag stig_id: 'GEN005770'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29159r485373_fix'
  tag 'documentable'
  tag legacy: ['V-22493', 'SV-26816']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
