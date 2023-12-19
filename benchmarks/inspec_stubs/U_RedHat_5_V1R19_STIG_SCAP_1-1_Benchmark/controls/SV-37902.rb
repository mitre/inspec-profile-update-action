control 'SV-37902' do
  title 'The /etc/news/incoming.conf file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the "incoming.conf" file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/incoming.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22502'
  tag rid: 'SV-37902r2_rule'
  tag stig_id: 'GEN006270'
  tag gtitle: 'GEN006270'
  tag fix_id: 'F-32396r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
