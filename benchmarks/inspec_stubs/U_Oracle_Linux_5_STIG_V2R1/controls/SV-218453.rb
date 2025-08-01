control 'SV-218453' do
  title 'The at.deny file must not have an extended ACL.'
  desc 'The "at" daemon control files restrict access to scheduled job manipulation and must be protected.  Unauthorized modification of the at.deny file could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/at.deny
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/at.deny'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19928r562516_chk'
  tag severity: 'medium'
  tag gid: 'V-218453'
  tag rid: 'SV-218453r603259_rule'
  tag stig_id: 'GEN003255'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19926r562517_fix'
  tag 'documentable'
  tag legacy: ['V-22393', 'SV-64357']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
