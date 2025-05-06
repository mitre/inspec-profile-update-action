control 'SV-234873' do
  title 'The SUSE operating system must display the date and time of the last successful account logon upon logon.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify the SUSE operating system users are provided with feedback on when account accesses last occurred.

Check that "pam_lastlog" is used and not silent with the following command:

> grep pam_lastlog /etc/pam.d/login

session required pam_lastlog.so showfailed 

If "pam_lastlog" is missing from "/etc/pam.d/login" file, the "silent" option is present, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/login". 

Add the following line to the top of "/etc/pam.d/login":

session required pam_lastlog.so showfailed'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38061r618888_chk'
  tag severity: 'low'
  tag gid: 'V-234873'
  tag rid: 'SV-234873r622137_rule'
  tag stig_id: 'SLES-15-020080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38024r618889_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
