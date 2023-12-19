control 'SV-209047' do
  title 'The system default umask in /etc/login.defs must be 077.'
  desc 'The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.'
  desc 'check', 'Verify the "umask" setting is configured correctly in the "/etc/login.defs" file by running the following command: 

# grep -i "umask" /etc/login.defs

All output must show the value of "umask" set to 077, as shown in the below: 

# grep -i "umask" /etc/login.defs
UMASK 077

If the above command returns no output, or if the umask is configured incorrectly, this is a finding.'
  desc 'fix', 'To ensure the default umask controlled by "/etc/login.defs" is set properly, add or correct the "umask" setting in "/etc/login.defs" to read as follows: 

UMASK 077'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9300r357926_chk'
  tag severity: 'low'
  tag gid: 'V-209047'
  tag rid: 'SV-209047r793768_rule'
  tag stig_id: 'OL6-00-000345'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9300r357927_fix'
  tag 'documentable'
  tag legacy: ['SV-64873', 'V-50667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
