control 'SV-222402' do
  title 'The application must ensure encrypted assertions, or equivalent confidentiality protections are used when assertion data is passed through an intermediary, and confidentiality of the assertion data is required when passing through the intermediary.'
  desc '<0> [object Object]'
  desc 'check', 'Ask the application representative for the design document.

Review the design document for web services using WS-Security tokens.  

If the application does not utilize WS-Security tokens, this check is not applicable.

Verify all WS-Security tokens are transmitted via an approved encryption method.

If the design document does not exist, or does not indicate all WS-Security tokens are only transmitted via an approved encryption method, this is a finding.'
  desc 'fix', 'Encrypt assertions or use equivalent confidentiality when sensitive assertion data is passed through an intermediary.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24072r493114_chk'
  tag severity: 'medium'
  tag gid: 'V-222402'
  tag rid: 'SV-222402r508029_rule'
  tag stig_id: 'APSC-DV-000220'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24061r493115_fix'
  tag legacy: ['SV-83907', 'V-69285']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
