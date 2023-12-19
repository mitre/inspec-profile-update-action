control 'SV-26817' do
  title 'The NFS exports configuration file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files. Excessive permissions on the NFS export configuration file could allow unauthorized modification of the file, which could result in Denial of Service to authorized NFS exports and the creation of additional unauthorized exports.'
  desc 'check', %q(Check the mode of the NFS export configuration file.
# echo `ls -lL /etc/dfs/dfstab` | sed -e 's/^[ \t]*//' |  tr '\011' ' ' | tr -s ' ' | cut -f 1,1 -d " "

If the permissions include a + the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /etc/dfs/dfstab'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35032r2_chk'
  tag severity: 'low'
  tag gid: 'V-22493'
  tag rid: 'SV-26817r1_rule'
  tag stig_id: 'GEN005770'
  tag gtitle: 'GEN005770'
  tag fix_id: 'F-24060r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
