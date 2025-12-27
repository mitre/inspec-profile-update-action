control 'SV-242617' do
  title 'The Cisco ISE must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.

If the administrator enters an incorrect password three times, the Admin portal locks the account, adds a log entry in the Server Administrator Logins report, and suspends the credentials until it is reset.'
  desc 'check', 'Log in to the CLI via SSH or the console. View the Cisco ISE configuration. Verify the following are set:

accountlocking enable
accountlocking unlocktime 900

If a lockout for local accounts is not configured, this is a finding.'
  desc 'fix', 'Log in to the CLI via SSH or the console.

Configure using CLI to enable and configure lockout. After three failed login attempts, the account will be locked for 15 minutes.

Set accountlocking enable
Set accountlocking unlocktime 900'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45892r714159_chk'
  tag severity: 'medium'
  tag gid: 'V-242617'
  tag rid: 'SV-242617r714161_rule'
  tag stig_id: 'CSCO-NM-000110'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-45849r717036_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
