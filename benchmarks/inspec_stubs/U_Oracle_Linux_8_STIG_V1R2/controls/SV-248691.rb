control 'SV-248691' do
  title 'OL 8 must require the maximum number of repeating characters be limited to three when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
OL 8 uses "pwquality" as a mechanism to enforce password complexity. The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.'
  desc 'check', 'Check for the value of the "maxrepeat" option in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep maxrepeat /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
 
/etc/security/pwquality.conf:maxrepeat = 3 
 
If the value of "maxrepeat" is set to more than "3" or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option. 
 
Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory: 
 
maxrepeat = 3'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52125r779637_chk'
  tag severity: 'medium'
  tag gid: 'V-248691'
  tag rid: 'SV-248691r779639_rule'
  tag stig_id: 'OL08-00-020150'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-52079r779638_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
