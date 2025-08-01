control 'SV-227762' do
  title 'The at.deny file must not have an extended ACL.'
  desc 'The "at" daemon control files restrict access to scheduled job manipulation and must be protected.  Unauthorized modification of the at.deny file could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/cron.d/at.deny
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/cron.d/at.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29924r488870_chk'
  tag severity: 'medium'
  tag gid: 'V-227762'
  tag rid: 'SV-227762r603266_rule'
  tag stig_id: 'GEN003255'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29912r488871_fix'
  tag 'documentable'
  tag legacy: ['V-22393', 'SV-26560']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
