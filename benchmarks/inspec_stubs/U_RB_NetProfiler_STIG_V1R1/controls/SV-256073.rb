control 'SV-256073' do
  title 'The Riverbed NetProfiler must enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 30 minutes, at a minimum.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. in NetProfiler, the default "Number of log-in attempts before account is locked" is 3, and the default "Number of minutes to keep account locked" is 30.'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Check under "Log-in Settings". 

If the "Number of log-in attempts before an account is locked" is not set to "3", and the "Number of minutes to keep account locked" is not set to "30", this is a finding.'
  desc 'fix', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Under "Log-in Settings", change the "Number of log-in attempts before account is locked" to "3", and change the "Number of minutes to keep account locked" to "30". 

Click "OK" to save the settings.

Note that the DOD minimum setting is 15; however, the product minimum is 30.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59747r882725_chk'
  tag severity: 'medium'
  tag gid: 'V-256073'
  tag rid: 'SV-256073r882727_rule'
  tag stig_id: 'RINP-DM-000008'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-59690r882726_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
