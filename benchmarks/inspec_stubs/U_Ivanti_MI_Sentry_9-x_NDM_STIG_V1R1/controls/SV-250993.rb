control 'SV-250993' do
  title 'MobileIron Sentry must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Where passwords are used, confirm that MobileIron Sentry server enforces password complexity by requiring that at least one special character be used. 

If MobileIron Sentry server does not require that at least one special character be used in each password, this is a finding.

1. Log in to the System Manager of Sentry. 
2. Go to Security >> Identity Source >> Password. 
3. Verify "Special Character" is checked.

If "Special Character" is not checked, this is a finding.'
  desc 'fix', 'Configure MobileIron Sentry server to enforce password complexity by requiring that at least one special character be used.

1. Log in to the System Manager of Sentry. 
2. Go to Security >> Password. 
3. Check "Special Character".
4. Select "Apply".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54428r802199_chk'
  tag severity: 'medium'
  tag gid: 'V-250993'
  tag rid: 'SV-250993r802201_rule'
  tag stig_id: 'MOIS-ND-000460'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-54382r802200_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
