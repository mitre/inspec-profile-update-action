control 'SV-206476' do
  title 'The Central Log Server must be configured to enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce 24 hours/1 day as the minimum password lifetime.

If the Central Log Server is not configured to enforce 24 hours/1 day as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to enforce 24 hours/1 day as the minimum password lifetime.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6736r285672_chk'
  tag severity: 'low'
  tag gid: 'V-206476'
  tag rid: 'SV-206476r397588_rule'
  tag stig_id: 'SRG-APP-000173-AU-002560'
  tag gtitle: 'SRG-APP-000173'
  tag fix_id: 'F-6736r285673_fix'
  tag 'documentable'
  tag legacy: ['SV-96069', 'V-81355']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
