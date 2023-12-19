control 'SV-253905' do
  title 'The Juniper EX switch must be configured to enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Where passwords are used, confirm that the network device and associated authentication server enforces password complexity by requiring that at least one uppercase character be used. This requirement may be verified by demonstration, configuration review, or validated test results.

[edit system login password]
:
minimum-uppercases 1;
:

If the network device and associated authentication server does not require that at least one uppercase character be used in each password, this is a finding.'
  desc 'fix', 'Configure the network device and associated authentication server to enforce password complexity by requiring that at least one uppercase character be used.

set system login password minimum-uppercases 1'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57357r843746_chk'
  tag severity: 'medium'
  tag gid: 'V-253905'
  tag rid: 'SV-253905r879603_rule'
  tag stig_id: 'JUEX-NM-000280'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-57308r843747_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
