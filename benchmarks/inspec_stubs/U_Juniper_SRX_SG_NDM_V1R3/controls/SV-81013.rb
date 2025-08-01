control 'SV-81013' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce password complexity by requiring at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the default local password enforces password complexity by requiring at least one numeric character be used.

[edit]
show system login password

If the minimum numerics are not set to at least 1, this is a finding.'
  desc 'fix', 'Configure the default local password to enforce password complexity by requiring at least one numeric character be used.

[edit]
set system login password minimum -numerics to 1'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67169r2_chk'
  tag severity: 'medium'
  tag gid: 'V-66523'
  tag rid: 'SV-81013r2_rule'
  tag stig_id: 'JUSX-DM-000132'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-72599r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
