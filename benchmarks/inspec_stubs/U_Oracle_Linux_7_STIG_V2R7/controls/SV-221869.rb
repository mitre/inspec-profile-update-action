control 'SV-221869' do
  title 'The Oracle Linux operating system must display the date and time of the last successful account logon upon logon.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify users are provided with feedback on when account accesses last occurred.

Check that "pam_lastlog" is used and not silent with the following command:

# grep pam_lastlog /etc/pam.d/postlogin
session required pam_lastlog.so showfailed

If "pam_lastlog" is missing from "/etc/pam.d/postlogin" file, or the silent option is present, this is a finding.'
  desc 'fix', 'Configure the operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/postlogin". 

Add the following line to the top of "/etc/pam.d/postlogin":

session required pam_lastlog.so showfailed'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23584r419679_chk'
  tag severity: 'low'
  tag gid: 'V-221869'
  tag rid: 'SV-221869r603260_rule'
  tag stig_id: 'OL07-00-040530'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23573r419680_fix'
  tag 'documentable'
  tag legacy: ['V-99477', 'SV-108581']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
