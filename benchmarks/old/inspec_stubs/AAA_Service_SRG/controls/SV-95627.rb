control 'SV-95627' do
  title 'AAA Services must be configured to enforce 24 hours as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.

Where passwords are used, such as temporary or emergency accounts, verify AAA Services are configured to enforce 24 hours as the minimum password lifetime. When the AAA Services configuration setting is for "1 day", it is required that the length be 24 hours.

If AAA Services are not configured to enforce 24 hours as the minimum password lifetime, this is a finding.'
  desc 'fix', 'Configure AAA Services to enforce 24 hours as the minimum password lifetime. When the AAA Services configuration setting is for "1 day", it is required that the length be 24 hours. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80655r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80917'
  tag rid: 'SV-95627r1_rule'
  tag stig_id: 'SRG-APP-000173-AAA-000530'
  tag gtitle: 'SRG-APP-000173-AAA-000530'
  tag fix_id: 'F-87773r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
