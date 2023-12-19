control 'SV-223219' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce password complexity by requiring at least one upper-case character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the default local password enforces password complexity by requiring at least one upper-case character be used.

[edit]
show system login password

If the minimum-upper-cases is not set to at least 1, this is a finding.'
  desc 'fix', 'Configure the default local password to enforce password complexity by requiring at least one upper-case character be used.

[edit]
set system login password minimum-upper-cases 1'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24892r513344_chk'
  tag severity: 'medium'
  tag gid: 'V-223219'
  tag rid: 'SV-223219r513346_rule'
  tag stig_id: 'JUSX-DM-000130'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-24880r513345_fix'
  tag 'documentable'
  tag legacy: ['SV-81009', 'V-66519']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
