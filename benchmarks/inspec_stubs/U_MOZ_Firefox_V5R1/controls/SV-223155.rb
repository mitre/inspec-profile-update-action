control 'SV-223155' do
  title 'Firefox automatically updates installed add-ons and plugins.'
  desc 'Set this to false to disable checking for updated versions of the Extensions/Themes.  Automatic updates from untrusted sites puts the enclave at risk of attack and may override security settings.'
  desc 'check', 'Type "about:config" in the browser window. Verify the preference “extensions.update.enabled” is set to "false" and locked. 

Criteria: If the parameter is set incorrectly, then this is a finding. If this setting is not locked, then this is a finding.'
  desc 'fix', 'Set the preference “extensions.update.enabled” value to "false" and lock using the Mozilla.cfg file.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24828r531282_chk'
  tag severity: 'medium'
  tag gid: 'V-223155'
  tag rid: 'SV-223155r612236_rule'
  tag stig_id: 'DTBF090'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24816r531283_fix'
  tag 'documentable'
  tag legacy: ['SV-59603', 'V-19742']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
