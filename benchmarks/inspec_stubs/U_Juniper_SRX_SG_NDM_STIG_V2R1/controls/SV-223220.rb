control 'SV-223220' do
  title 'For local accounts using password authentication (i.e., the root account and the account of last resort), the Juniper SRX Services Gateway must enforce password complexity by requiring at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the default local password enforces password complexity by requiring at least one lower-case character be used.

[edit]
show system login password

If the minimum-lower-cases is not set to at least 1, this is a finding.'
  desc 'fix', 'Configure the default local password to enforce password complexity by requiring at least one lower-case character be used.

[edit]
set system login password minimum-lower-cases 1'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24893r513347_chk'
  tag severity: 'medium'
  tag gid: 'V-223220'
  tag rid: 'SV-223220r513349_rule'
  tag stig_id: 'JUSX-DM-000131'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-24881r513348_fix'
  tag 'documentable'
  tag legacy: ['SV-81011', 'V-66521']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
