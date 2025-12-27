control 'SV-242239' do
  title 'The TippingPoint SMS must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'In the SMS client, ensure the SMS password complexity requirements are met.

1. Under Security, click Edit and Preferences. 
2. If the security level is set to anything except "3 - High", this is a finding. This setting ensures a 15-character minimum, uppercase, lowercase, numbers, and symbols are used.'
  desc 'fix', 'In the SMS client, ensure the SMS password complexity requirements are met. 

1. Under Security, click Edit and Preferences. 
2. Change security level to "3 - High". This setting ensures a 15-character minimum, uppercase, lowercase, numbers, and symbols are used.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45514r710722_chk'
  tag severity: 'medium'
  tag gid: 'V-242239'
  tag rid: 'SV-242239r710724_rule'
  tag stig_id: 'TIPP-NM-000250'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-45472r710723_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
