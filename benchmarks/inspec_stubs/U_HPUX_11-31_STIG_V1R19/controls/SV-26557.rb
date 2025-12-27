control 'SV-26557' do
  title 'The at.deny file must have mode 0600 or less permissive.'
  desc 'The at daemon control files restrict access to scheduled job manipulation and must be protected. Unauthorized modification of the at.deny file could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'check', 'Check the mode of the file.
# ls -lL /var/adm/cron/at.deny

If the file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the file.
# chmod 0600 /var/adm/cron/at.deny'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36476r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22392'
  tag rid: 'SV-26557r1_rule'
  tag stig_id: 'GEN003252'
  tag gtitle: 'GEN003252'
  tag fix_id: 'F-31819r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
