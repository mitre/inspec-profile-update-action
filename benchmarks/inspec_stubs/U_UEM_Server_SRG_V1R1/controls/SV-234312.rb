control 'SV-234312' do
  title 'The UEM server must retain the access banner until the user acknowledges acceptance of the access conditions.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the application. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The application must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK". 

Satisfies:FTA_TAB.1.1 
Reference:PP-MDM-413003'
  desc 'check', 'Verify the UEM server retains the access banner until the user acknowledges acceptance of the access conditions.

If the UEM server does not retain the access banner until the user acknowledges acceptance of the access conditions, this is a finding.'
  desc 'fix', 'Configure the UEM server to retain the access banner until the user acknowledges acceptance of the access conditions.'
  impact 0.3
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37497r613946_chk'
  tag severity: 'low'
  tag gid: 'V-234312'
  tag rid: 'SV-234312r617355_rule'
  tag stig_id: 'SRG-APP-000069-UEM-000038'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-37462r613947_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
