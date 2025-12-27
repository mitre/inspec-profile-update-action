control 'SV-248709' do
  title 'All OL 8 passwords must contain at least one special character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 
 
OL 8 uses "pwquality" as a mechanism to enforce password complexity. Note that to require special characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".'
  desc 'check', 'Verify the value for "ocredit" in "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep -r ocredit /etc/security/pwquality.conf*
 
/etc/security/pwquality.conf:ocredit = -1 
 
If the value of "ocredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory:

ocredit = -1

Remove any configurations that conflict with the above value.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52143r833235_chk'
  tag severity: 'low'
  tag gid: 'V-248709'
  tag rid: 'SV-248709r858647_rule'
  tag stig_id: 'OL08-00-020280'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-52097r858646_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
