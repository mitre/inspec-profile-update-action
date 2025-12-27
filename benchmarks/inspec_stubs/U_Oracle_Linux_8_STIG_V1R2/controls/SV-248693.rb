control 'SV-248693' do
  title 'OL 8 must require the change of at least 8 characters when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
OL 8 uses "pwquality" as a mechanism to enforce password complexity. The "difok" option sets the number of characters in a password that must not be present in the old password.'
  desc 'check', 'Verify the value of the "difok" option in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep difok /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
 
/etc/security/pwquality.conf:difok = 8 
 
If the value of "difok" is set to less than "8" or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option. 
 
Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory: 
 
difok = 8'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52127r779643_chk'
  tag severity: 'low'
  tag gid: 'V-248693'
  tag rid: 'SV-248693r779645_rule'
  tag stig_id: 'OL08-00-020170'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-52081r779644_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
