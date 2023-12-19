control 'SV-209046' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9299r357923_chk'
  tag severity: 'low'
  tag gid: 'V-209046'
  tag rid: 'SV-209046r793767_rule'
  tag stig_id: 'OL6-00-000344'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9299r357924_fix'
  tag 'documentable'
  tag legacy: ['V-50669', 'SV-64875']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
