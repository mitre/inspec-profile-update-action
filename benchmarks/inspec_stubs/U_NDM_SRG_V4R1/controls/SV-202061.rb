control 'SV-202061' do
  title 'The network device must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Where passwords are used, confirm that the network device and associated authentication server enforces password complexity by requiring that at least one numeric character be used. This requirement may be verified by demonstration, configuration review, or validated test results.

If the network device and associated authentication server does not require that at least one numeric character be used in each password, this is a finding.'
  desc 'fix', 'Configure the network device and associated authentication server to enforce password complexity by requiring that at least one numeric character be used.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2187r381773_chk'
  tag severity: 'medium'
  tag gid: 'V-202061'
  tag rid: 'SV-202061r397513_rule'
  tag stig_id: 'SRG-APP-000168-NDM-000256'
  tag gtitle: 'SRG-APP-000168'
  tag fix_id: 'F-2188r381774_fix'
  tag 'documentable'
  tag legacy: ['SV-69369', 'V-55123']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
