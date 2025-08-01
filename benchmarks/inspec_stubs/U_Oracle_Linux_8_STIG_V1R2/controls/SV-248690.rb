control 'SV-248690' do
  title 'OL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
OL 8 uses "pwquality" as a mechanism to enforce password complexity. The "maxclassrepeat" option sets the maximum number of allowed same consecutive characters in the same class in the new password.'
  desc 'check', 'Check for the value of the "maxclassrepeat" option in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep maxclassrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
 
/etc/security/pwquality.conf:maxclassrepeat = 4 
 
If the value of "maxclassrepeat" is set to "0", more than "4" or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to require the change of the number of repeating characters of the same character class when passwords are changed by setting the "maxclassrepeat" option. 
 
Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory: 
 
maxclassrepeat = 4'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52124r818659_chk'
  tag severity: 'medium'
  tag gid: 'V-248690'
  tag rid: 'SV-248690r818660_rule'
  tag stig_id: 'OL08-00-020140'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-52078r779635_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
