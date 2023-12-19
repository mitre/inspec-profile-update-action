control 'SV-223157' do
  title 'Network shell protocol is enabled in FireFox.'
  desc 'Although current versions of Firefox have this set to disabled by default, use of this option can be harmful.  This would allow the browser to access the Windows shell. This could allow access to the
underlying system.  This check verifies that the default setting has not been changed.'
  desc 'check', 'Procedure: Open a browser window, type "about:config" in the address bar. 

Criteria: If the value of "network.protocol-handler.external.shell" is not "false" or is not locked, then this is a finding.'
  desc 'fix', 'Procedure: Set the value of "network.protocol-handler.external.shell" to "false" and lock using the Mozilla.cfg file.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox'
  tag check_id: 'C-24830r531288_chk'
  tag severity: 'medium'
  tag gid: 'V-223157'
  tag rid: 'SV-223157r612236_rule'
  tag stig_id: 'DTBF105'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24818r531289_fix'
  tag 'documentable'
  tag legacy: ['SV-16710', 'V-15771']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
