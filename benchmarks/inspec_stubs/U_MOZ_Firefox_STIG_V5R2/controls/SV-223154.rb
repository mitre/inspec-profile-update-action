control 'SV-223154' do
  title 'Firefox automatically checks for updated version of installed Search plugins.'
  desc 'Updates need to be controlled and installed from authorized and trusted servers.  This setting overrides a number of other settings which may direct the application to access external URLs.'
  desc 'check', 'Type "about:config" in the browser window. Verify the preference "browser.search.update”  is set to "false" and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference  "browser.search.update"  is set and locked to the value of “False”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24827r531279_chk'
  tag severity: 'medium'
  tag gid: 'V-223154'
  tag rid: 'SV-223154r612236_rule'
  tag stig_id: 'DTBF085'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24815r531280_fix'
  tag 'documentable'
  tag legacy: ['SV-21890', 'V-19744']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
