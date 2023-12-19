control 'SV-242617' do
  title 'The Cisco ISE must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.

If the administrator enters an incorrect password three times, the Admin portal locks the account, adds a log entry in the Server Administrator Logins report, and suspends the credentials until it is reset.'
  desc 'check', 'Verify ISE will disable accounts for at least 15 minutes after a maximum of three consecutive invalid logon attempts. 

From web admin portal:
1. Choose Administration >> System >> Admin Access >> Authentication >> Lock/Suspend Settings.
2. Verify the "Take action after [ ] failed attempts" setting is set to a value of 3 or lower.
3. Verify the "Suspend account for [ ] minutes" setting is selected and set to be 15 minutes or higher 

If the lockout for admin accounts is not configured to lock the account after a maximum of three incorrect passwords are attempted, this is a finding.

If the lockout for admin accounts is not configured to lock the account for a minimum of 15 minutes, this is a finding.'
  desc 'fix', 'Configure ISE to disable accounts  for at least 15 minutes after a maximum of three consecutive invalid logon attempts. 

From web admin portal:
1. Choose Administration >> System >> Admin Access >> Authentication >> Lock/Suspend Settings.
2. Configure the "Take action after [ ] failed attempts" setting to be set to a value of 3 or lower.
3. Check the "Suspend account for [ ] minutes" setting and set to be 15 minutes or higher.
4. Click Save.

Note: This setting will propagate to the ADE-OS applying the settings for the CLI accounts as well.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45892r822784_chk'
  tag severity: 'medium'
  tag gid: 'V-242617'
  tag rid: 'SV-242617r879546_rule'
  tag stig_id: 'CSCO-NM-000110'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-45849r822785_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
