control 'SV-217140' do
  title 'The SUSE operating system must display the date and time of the last successful account logon upon logon.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'Verify the SUSE operating system users are provided with feedback on when account accesses last occurred.

Check that "pam_lastlog" is used and not silent with the following command:

> grep pam_lastlog /etc/pam.d/login

session required pam_lastlog.so showfailed 

If "pam_lastlog" is missing from "/etc/pam.d/login" file, the "silent" option is present, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/login". 

Add the following line to the top of "/etc/pam.d/login":

session     required      pam_lastlog.so showfailed'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18368r646708_chk'
  tag severity: 'low'
  tag gid: 'V-217140'
  tag rid: 'SV-217140r858540_rule'
  tag stig_id: 'SLES-12-010390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18366r369577_fix'
  tag 'documentable'
  tag legacy: ['SV-91831', 'V-77135']
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
