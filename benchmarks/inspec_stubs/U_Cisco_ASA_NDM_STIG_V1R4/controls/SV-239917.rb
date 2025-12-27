control 'SV-239917' do
  title 'The Cisco ASA must be configured to enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the ASA configuration to verify that it is compliant with this requirement as shown in the example below.

password-policy minimum-numeric 1

If the Cisco ASA is not configured to enforce password complexity by requiring that at least one numeric character be used, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to enforce password complexity by requiring that at least one numeric character be used as shown in the example below.

ASA(config)# password-policy minimum-numeric 1'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43150r666112_chk'
  tag severity: 'medium'
  tag gid: 'V-239917'
  tag rid: 'SV-239917r879605_rule'
  tag stig_id: 'CASA-ND-000550'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-43109r666113_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
