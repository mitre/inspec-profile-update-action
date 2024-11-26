control 'SV-230967' do
  title 'Forescout must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', '1. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2. Verify the fourth "password must contain at least" is checked. 
3. Verify there is 1 (or higher) in the "in the special character" configuration box.

If the Forescout does not enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure Forescout to require a minimum of one special character.

1. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2. Check the fourth "password must contain at least" option.
3. Add a 1 (or higher) in the "in the special character" configuration box.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33897r603740_chk'
  tag severity: 'medium'
  tag gid: 'V-230967'
  tag rid: 'SV-230967r615886_rule'
  tag stig_id: 'FORE-NM-000410'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-33870r603741_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
