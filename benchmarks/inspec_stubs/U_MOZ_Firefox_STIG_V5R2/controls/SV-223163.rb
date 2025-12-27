control 'SV-223163' do
  title 'FireFox is not configured to block pop-up windows.'
  desc 'Popup windows may be used to launch an attack within a new browser window with altered settings. This setting blocks popup windows created while the page is loading.'
  desc 'check', 'In About:Config, verify that the preference name “dom.disable_window_open_feature.status " is set to “true” and locked.

Criteria: If the parameter is set incorrectly, then this is a finding.  If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference  "dom.disable_window_open_feature.status "  is set and locked to the value of “true”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24836r531306_chk'
  tag severity: 'medium'
  tag gid: 'V-223163'
  tag rid: 'SV-223163r612236_rule'
  tag stig_id: 'DTBF180'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24824r531307_fix'
  tag 'documentable'
  tag legacy: ['SV-16717', 'V-15778']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
