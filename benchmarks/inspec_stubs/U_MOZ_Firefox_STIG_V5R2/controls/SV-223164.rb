control 'SV-223164' do
  title 'FireFox is configured to allow JavaScript to move or resize windows.'
  desc 'JavaScript can make changes to the browser’s appearance. This activity can help disguise an attack taking place in a minimized background window.  Set browser setting to prevent scripts on visited websites from moving and resizing browser windows.'
  desc 'check', 'In About:Config, verify that the preference name “dom.disable_window_move_resize" is set and locked to “true”.

Criteria: If the parameter is set incorrectly, then this is a finding.  If the setting is not locked, then this is a finding.'
  desc 'fix', 'Ensure the preference  "dom.disable_window_move_resize"  is set and locked to the value of “true”.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24837r531309_chk'
  tag severity: 'medium'
  tag gid: 'V-223164'
  tag rid: 'SV-223164r612236_rule'
  tag stig_id: 'DTBF181'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24825r531310_fix'
  tag 'documentable'
  tag legacy: ['SV-16718', 'V-15779']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
