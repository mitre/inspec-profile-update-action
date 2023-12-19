control 'SV-239918' do
  title 'The Cisco ASA must be configured to enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the ASA configuration to verify that it is compliant with this requirement as shown in the example below.

password-policy minimum-special 1

If the Cisco ASA is not configured to enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to enforce password complexity by requiring that at least one special character be used as shown in the example below.

ASA(config)# password-policy minimum-special 1'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43151r666115_chk'
  tag severity: 'medium'
  tag gid: 'V-239918'
  tag rid: 'SV-239918r666117_rule'
  tag stig_id: 'CASA-ND-000570'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-43110r666116_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
