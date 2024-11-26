control 'SV-26558' do
  title 'The at.deny file must not have an extended ACL.'
  desc 'The "at" daemon control files restrict access to scheduled job manipulation and must be protected.  Unauthorized modification of the at.deny file could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/at.deny
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/at.deny'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22393'
  tag rid: 'SV-26558r1_rule'
  tag stig_id: 'GEN003255'
  tag gtitle: 'GEN003255'
  tag fix_id: 'F-31412r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
