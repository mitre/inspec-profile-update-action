control 'SV-256081' do
  title 'The Riverbed NetProfiler must configure the local account password to "require mixed case".'
  desc 'Use of complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using public key infrastructure (PKI) is not available and for the account of last resort and root account.

'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click the "Settings" button. 

Check under "Password Requirements". 

If the "Require mixed case" rule is not checked, this is a finding.'
  desc 'fix', 'Require the user password to have at least one uppercase and one lowercase character.

Go to Administration >> Account Management >> User Accounts. 

Click the "Settings" button. 

Under "Password Requirements", select the "Require mixed case" rule.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59755r882749_chk'
  tag severity: 'medium'
  tag gid: 'V-256081'
  tag rid: 'SV-256081r882751_rule'
  tag stig_id: 'RINP-DM-000032'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-59698r882750_fix'
  tag satisfies: ['SRG-APP-000166-NDM-000254', 'SRG-APP-000167-NDM-000255']
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
