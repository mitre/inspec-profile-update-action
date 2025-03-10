control 'SV-242232' do
  title 'The TippingPoint SMS must limit total number of user sessions for privileged uses to a maximum of 10.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of currently allowed administrator sessions is a best practice that lowers the risk of DoS attacks.'
  desc 'check', '1. Log in to the SMS client. 
2. Select >> "Edit" >> "Preferences". Select "Security" under "Session Preferences".
3. Verify the setting for the "limit number of total and user sessions" option is checked.
4. Verify the active sessions allowed on SMS option has a numeric value of 10 or less.

If the TippingPoint SMS does not limit total number of user sessions for privileged uses to a maximum of 10, this is a finding.'
  desc 'fix', '1. Log in to the SMS client. 
2. Select >> "Edit" >> "Preferences". Select "Security" under "Session Preferences". Click the check box for "Limit number of total and user sessions". 
3. Type 10 or less for the number of active sessions allowed on SMS. 
4. Click OK.'
  impact 0.3
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45507r710701_chk'
  tag severity: 'low'
  tag gid: 'V-242232'
  tag rid: 'SV-242232r710703_rule'
  tag stig_id: 'TIPP-NM-000011'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-45465r710702_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
