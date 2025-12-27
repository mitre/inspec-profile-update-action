control 'SV-250992' do
  title 'MobileIron Sentry must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Where passwords are used, confirm that MobileIron Sentry server enforces password complexity by requiring that at least one numeric character be used. This requirement may be verified by demonstration, configuration review, or validated test results.

If MobileIron Sentry server does not require that at least one numeric character be used in each password, this is a finding.

1. Log in to the System Manager of Sentry. 
2. Go to Security >> Identity Source >> Password. 
3. Verify "Numeric" is checked.

If "Numeric" is not checked, this is a finding.'
  desc 'fix', 'Configure MobileIron Sentry server to enforce password complexity by requiring that at least one numeric character be used.

1. Log in to the System Manager of Sentry. 
2. Go to Security >> Password. 
3. Check "Numeric". 
4. Select "Apply".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54427r802196_chk'
  tag severity: 'medium'
  tag gid: 'V-250992'
  tag rid: 'SV-250992r802198_rule'
  tag stig_id: 'MOIS-ND-000450'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-54381r802197_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
