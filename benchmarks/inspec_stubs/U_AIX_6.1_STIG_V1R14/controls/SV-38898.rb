control 'SV-38898' do
  title 'The /etc/news/hosts.nntp file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the numbers of the files.  Excessive permissions on the hosts.nntp file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the hosts.nntp file.
# find / -type f -name hosts.nntp 
# aclget < hosts.nntp file >
If extended permissions are enabled, the file has an extended ACL,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the hosts.nntp file.  
#acledit < hosts.nntp file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22502'
  tag rid: 'SV-38898r1_rule'
  tag stig_id: 'GEN006270'
  tag gtitle: 'GEN006270'
  tag fix_id: 'F-33151r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
