control 'SV-248717' do
  title 'OL 8 must display the date and time of the last successful account logon upon logon.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last occurred with the following command: 
 
$ sudo grep pam_lastlog /etc/pam.d/postlogin 
 
session required pam_lastlog.so showfailed 
 
If "pam_lastlog" is missing from the "/etc/pam.d/postlogin" file or the silent option is present, this is a finding.'
  desc 'fix', 'Configure OL 8 to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/postlogin". 
 
Add the following line to the top of "/etc/pam.d/postlogin": 
 
session required pam_lastlog.so showfailed'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52151r779715_chk'
  tag severity: 'low'
  tag gid: 'V-248717'
  tag rid: 'SV-248717r858591_rule'
  tag stig_id: 'OL08-00-020340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52105r779716_fix'
  tag 'documentable'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
