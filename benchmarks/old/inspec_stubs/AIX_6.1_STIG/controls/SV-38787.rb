control 'SV-38787' do
  title 'The at.deny file must have mode 0640 or less permissive.'
  desc 'The at daemon control files restrict access to scheduled job manipulation and must be protected. Unauthorized modification of the at.deny file could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'check', 'Determine the mode of the at.deny file.
# ls -lL /var/adm/cron/at.deny
If the mode of the at.deny file is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the at.deny file to 0640.
# chmod 0640 /var/adm/cron/at.deny'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37211r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22392'
  tag rid: 'SV-38787r1_rule'
  tag stig_id: 'GEN003252'
  tag gtitle: 'GEN003252'
  tag fix_id: 'F-32478r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
