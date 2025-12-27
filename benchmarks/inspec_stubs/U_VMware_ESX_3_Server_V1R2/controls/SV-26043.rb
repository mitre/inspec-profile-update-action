control 'SV-26043' do
  title 'The at.deny file must have mode 0600 or less permissive.'
  desc 'The "at" daemon control files restrict access to scheduled job manipulation and must be protected. Unauthorized modification of the at.deny file could result in Denial-of-Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Determine the mode of the at.deny file.
# ls -lL at.deny
If the mode of the at.deny file is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the at.deny file to 0600.
# chmod 0600 at.deny'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29226r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22392'
  tag rid: 'SV-26043r1_rule'
  tag stig_id: 'GEN003252'
  tag gtitle: 'GEN003252'
  tag fix_id: 'F-26247r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
