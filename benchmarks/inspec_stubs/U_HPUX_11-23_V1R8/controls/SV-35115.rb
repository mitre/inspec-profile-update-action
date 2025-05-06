control 'SV-35115' do
  title 'The /etc/news/hosts.nntp file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files. Excessive permissions on the hosts.nntp file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# find / -type f -name hosts.nntp | xargs -n1 ls -lL 

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.

# chacl -z <path>/hosts.nntp'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34959r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22502'
  tag rid: 'SV-35115r1_rule'
  tag stig_id: 'GEN006270'
  tag gtitle: 'GEN006270'
  tag fix_id: 'F-30263r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
