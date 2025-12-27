control 'SV-242231' do
  title 'The TippingPoint SMS must limit the maximum number of concurrent active sessions to one for the account of last resort.'
  desc 'Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions is defined by DoD as one based on operational environment for each system.'
  desc 'check', '1. Log in to the SMS client. 
2. Select >> "Edit" >> "Preferences".  Select "Security" under "Session Preferences".
3. Verify the setting for the "limit number of total and user sessions" option is checked.
4. Verify the active sessions allowed for a user option has a numeric value of 1.

If the TippingPoint SMS does limit the maximum number of concurrent active sessions to one for the account of last resort, this is a finding.'
  desc 'fix', '1. Log in to the SMS client. 
2. Select >> "Edit" >> "Preferences".  Select "Security" under "Session Preferences". Click the check box for "Limit number of total and user sessions". 
3. Type 1 for the number of active sessions allowed for a user. 
4. Click OK.'
  impact 0.3
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45506r710698_chk'
  tag severity: 'low'
  tag gid: 'V-242231'
  tag rid: 'SV-242231r710700_rule'
  tag stig_id: 'TIPP-NM-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-45464r710699_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
