control 'SV-218075' do
  title 'The system default umask in /etc/profile must be 077.'
  desc 'The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.'
  desc 'check', 'Verify the "umask" setting is configured correctly in the "/etc/profile" file by running the following command: 

# grep "umask" /etc/profile

All output must show the value of "umask" set to 077, as shown in the below: 

# grep "umask" /etc/profile
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.'
  desc 'fix', 'To ensure the default umask controlled by "/etc/profile" is set properly, add or correct the "umask" setting in "/etc/profile" to read as follows: 

umask 077'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19556r377240_chk'
  tag severity: 'low'
  tag gid: 'V-218075'
  tag rid: 'SV-218075r603264_rule'
  tag stig_id: 'RHEL-06-000344'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19554r377241_fix'
  tag 'documentable'
  tag legacy: ['SV-50448', 'V-38647']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
