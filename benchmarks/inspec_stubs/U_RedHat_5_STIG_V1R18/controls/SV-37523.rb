control 'SV-37523' do
  title 'The "at" directory must not have an extended ACL.'
  desc 'If the "at" directory has an extended ACL, unauthorized users could be allowed to view or to edit files containing sensitive information within the "at" directory.  Unauthorized modifications could result in Denial of Service to authorized "at" jobs.'
  desc 'check', "Check the permissions of the directory.
# ls -lLd /var/spool/at
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the directory.
# setfacl --remove-all /var/spool/at'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36184r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22395'
  tag rid: 'SV-37523r1_rule'
  tag stig_id: 'GEN003410'
  tag gtitle: 'GEN003410'
  tag fix_id: 'F-31438r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
