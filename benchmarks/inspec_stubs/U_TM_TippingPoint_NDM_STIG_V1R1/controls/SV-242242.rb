control 'SV-242242' do
  title 'The TippingPoint SMS must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'In the SMS client, ensure the SMS password complexity requirements are met.

1. Under Security, click Edit and Preferences. 
2. If the security level is set to anything except "3 - High", this is a finding. This setting ensures a 15-character minimum, uppercase, lowercase, numbers, and symbols are used.'
  desc 'fix', 'In the SMS client, ensure the SMS password complexity requirements are met.

1. Under Security, click Edit and Preferences. 
2. Change security level to "3 - High". This setting ensures a 15-character minimum, uppercase, lowercase, numbers, and symbols are used.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45517r710731_chk'
  tag severity: 'medium'
  tag gid: 'V-242242'
  tag rid: 'SV-242242r710733_rule'
  tag stig_id: 'TIPP-NM-000280'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-45475r710732_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
