control 'SV-38899' do
  title 'The /etc/news/hosts.nntp.nolimit file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.

# find / -name hosts.nntp.nolimit

# aclget  < hosts.nntp.nolimit >
If the extended permissions are enabled the file has an extended ACL,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the hosts.nntp.nolimit file. 

# acledit < hosts.nntp.nolimit >

Set the extended permissions to disabled.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22503'
  tag rid: 'SV-38899r1_rule'
  tag stig_id: 'GEN006290'
  tag gtitle: 'GEN006290'
  tag fix_id: 'F-33154r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
