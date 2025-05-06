control 'SV-223175' do
  title 'Extension recommendations must be disabled.'
  desc 'The Recommended Extensions program will make it easier for users to discover extensions that have been reviewed for security, functionality, and user experience.'
  desc 'check', 'Type "about:config" in the address bar, verify that the preference name “extensions.htmlaboutaddons.recommendations.enabled" is set to “false” and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference “extensions.htmlaboutaddons.recommendations.enabled" is set and locked to the value of “false”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24848r531342_chk'
  tag severity: 'medium'
  tag gid: 'V-223175'
  tag rid: 'SV-223175r612236_rule'
  tag stig_id: 'DTBF225'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24836r531343_fix'
  tag 'documentable'
  tag legacy: ['SV-111847', 'V-102885']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
