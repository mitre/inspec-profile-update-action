control 'SV-248687' do
  title 'OL 8 must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
OL 8 uses pwquality as a mechanism to enforce password complexity. Note that in order to require uppercase characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".

'
  desc 'check', 'Verify the value for "ucredit" in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep ucredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
 
/etc/security/pwquality.conf:ucredit = -1 
 
If the value of "ucredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option. 
 
Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory: 
 
ucredit = -1'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52121r779625_chk'
  tag severity: 'low'
  tag gid: 'V-248687'
  tag rid: 'SV-248687r779627_rule'
  tag stig_id: 'OL08-00-020110'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-52075r779626_fix'
  tag satisfies: ['SRG-OS-000069-GPOS-00037', 'SRG-OS-000070-GPOS-00038']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)']
end
