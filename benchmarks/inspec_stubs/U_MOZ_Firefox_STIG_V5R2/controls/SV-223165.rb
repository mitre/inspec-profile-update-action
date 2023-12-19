control 'SV-223165' do
  title 'Firefox is configured to allow JavaScript to raise or lower windows.'
  desc 'JavaScript can make changes to the browser’s appearance. Allowing a website to use JavaScript to raise and lower browser windows may disguise an attack. Browser windows may not be set as active via JavaScript.'
  desc 'check', 'In About:Config, verify that the preference name “dom.disable_window_flip" is set and locked to “true”.

Criteria: If the parameter is set incorrectly, then this is a finding.  If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference  "dom.disable_window_flip"  is set and locked to the value of “true”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24838r531312_chk'
  tag severity: 'medium'
  tag gid: 'V-223165'
  tag rid: 'SV-223165r612236_rule'
  tag stig_id: 'DTBF182'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24826r531313_fix'
  tag 'documentable'
  tag legacy: ['SV-16927', 'V-15985']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
