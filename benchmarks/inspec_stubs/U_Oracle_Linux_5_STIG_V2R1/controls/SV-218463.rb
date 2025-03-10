control 'SV-218463' do
  title 'The at directory must not have an extended ACL.'
  desc 'If the "at" directory has an extended ACL, unauthorized users could be allowed to view or to edit files containing sensitive information within the "at" directory.  Unauthorized modifications could result in Denial of Service to authorized "at" jobs.'
  desc 'check', "Check the permissions of the directory.
# ls -lLd /var/spool/at
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the directory.
# setfacl --remove-all /var/spool/at'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19938r562546_chk'
  tag severity: 'medium'
  tag gid: 'V-218463'
  tag rid: 'SV-218463r603259_rule'
  tag stig_id: 'GEN003410'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19936r562547_fix'
  tag 'documentable'
  tag legacy: ['V-22395', 'SV-64289']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
