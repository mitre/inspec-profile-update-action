control 'SV-254211' do
  title 'Nutanix AOS must enforce a minimum 15 character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Confirm Nutanix AOS is configured to enforce a minimum 15 character password length.

$ sudo grep minlen /etc/security/pwquality.conf
minlen = 15

If the command does not return a "minlen" value of "15" or greater, this is a finding.'
  desc 'fix', 'Configure the password minimum length requirement of 15 characters by running the following command:

$ ncli cluster edit-cvm-security-params enable-high-strength-password=true'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57696r846719_chk'
  tag severity: 'medium'
  tag gid: 'V-254211'
  tag rid: 'SV-254211r846721_rule'
  tag stig_id: 'NUTX-OS-001260'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-57647r846720_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
