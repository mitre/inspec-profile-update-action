control 'SV-248711' do
  title 'OL 8 must prevent the use of dictionary words for passwords.'
  desc 'If OL 8 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify OL 8 prevents the use of dictionary words for passwords. 
 
Determine if the field "dictcheck" is set in the "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command: 
 
$ sudo grep dictcheck /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 
 
/etc/security/pwquality.conf:dictcheck=1 
 
If the "dictcheck" parameter is not set to "1" or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to prevent the use of dictionary words for passwords. 
 
Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory: 
 
dictcheck=1'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52145r779697_chk'
  tag severity: 'medium'
  tag gid: 'V-248711'
  tag rid: 'SV-248711r779699_rule'
  tag stig_id: 'OL08-00-020300'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-52099r779698_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
