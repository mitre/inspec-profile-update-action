control 'SV-219173' do
  title 'The Ubuntu operating system must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the Ubuntu operating system enforces password complexity by requiring that at least one lower-case character be used.

Determine if the field "lcredit" is set in the "/etc/security/pwquality.conf" file with the following command:

# grep -i "lcredit" /etc/security/pwquality.conf 
lcredit=-1

If the "lcredit" parameter is greater than "-1", or is commented out, this is a finding.'
  desc 'fix', 'Add or update the "/etc/security/pwquality.conf" file to contain the "lcredit" parameter:

lcredit=-1'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20898r304847_chk'
  tag severity: 'low'
  tag gid: 'V-219173'
  tag rid: 'SV-219173r610963_rule'
  tag stig_id: 'UBTU-18-010101'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-20897r304848_fix'
  tag 'documentable'
  tag legacy: ['V-100573', 'SV-109677']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
