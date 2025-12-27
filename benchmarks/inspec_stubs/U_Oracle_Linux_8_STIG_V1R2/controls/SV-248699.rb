control 'SV-248699' do
  title 'OL 8 passwords must have a minimum of 15 characters.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password. 
 
OL 8 uses "pwquality" as a mechanism to enforce password complexity. Configurations are set in the "etc/security/pwquality.conf" file. 
 
The "minlen", sometimes noted as minimum length, acts as a "score" of complexity based on the credit components of the "pwquality" module. By setting the credit components to a negative value, not only will those components be required, but they will not count toward the total "score" of "minlen". This will enable "minlen" to require a 15-character minimum.'
  desc 'check', 'Verify the operating system enforces a minimum 15-character password length. The "minlen" option sets the minimum number of characters in a new password. 
 
Check for the value of the "minlen" option in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep minlen /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
 
/etc/security/pwquality.conf:minlen = 15 
 
If the command does not return a "minlen" value of 15 or greater or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce a minimum 15-character password length. 
 
Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory: 
 
minlen = 15'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52133r779661_chk'
  tag severity: 'medium'
  tag gid: 'V-248699'
  tag rid: 'SV-248699r779663_rule'
  tag stig_id: 'OL08-00-020230'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-52087r779662_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
