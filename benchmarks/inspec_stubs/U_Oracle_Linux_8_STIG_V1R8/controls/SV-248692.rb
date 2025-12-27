control 'SV-248692' do
  title 'OL 8 must require the change of at least four character classes when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
OL 8 uses "pwquality" as a mechanism to enforce password complexity. The "minclass" option sets the minimum number of required classes of characters for the new password (digits, upper-case, lower-case, others).'
  desc 'check', 'Verify the value of the "minclass" option in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep -r minclass /etc/security/pwquality.conf*
 
/etc/security/pwquality.conf:minclass = 4 
 
If the value of "minclass" is set to less than "4" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure OL 8 to require the change of at least four character classes when passwords are changed by setting the "minclass" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory:

minclass = 4

Remove any configurations that conflict with the above value.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52126r833229_chk'
  tag severity: 'medium'
  tag gid: 'V-248692'
  tag rid: 'SV-248692r858641_rule'
  tag stig_id: 'OL08-00-020160'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-52080r858640_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
