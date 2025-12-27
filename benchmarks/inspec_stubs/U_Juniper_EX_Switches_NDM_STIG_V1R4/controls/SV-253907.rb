control 'SV-253907' do
  title 'The Juniper EX switch must be configured to enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Where passwords are used, confirm that the network device and associated authentication server enforces password complexity by requiring that at least one numeric character be used. This requirement may be verified by demonstration, configuration review, or validated test results.

[edit system login password]
:
minimum-numerics 1;
:

If the network device and associated authentication server does not require that at least one numeric character be used in each password, this is a finding.'
  desc 'fix', 'Configure the network device and associated authentication server to enforce password complexity by requiring that at least one numeric character be used.

set system login password minimum-numerics 1'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57359r843752_chk'
  tag severity: 'medium'
  tag gid: 'V-253907'
  tag rid: 'SV-253907r879605_rule'
  tag stig_id: 'JUEX-NM-000300'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-57310r843753_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
