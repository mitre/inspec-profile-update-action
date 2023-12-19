control 'SV-39258' do
  title 'The /etc/news/nnrp.access file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.

# find / -name nnrp.access
# ls -lL < nnrp.access >
If extended permissions are enabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the nnrp.access file. 

# acledit < nnrp.access >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22504'
  tag rid: 'SV-39258r1_rule'
  tag stig_id: 'GEN006310'
  tag gtitle: 'GEN006310'
  tag fix_id: 'F-33508r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
