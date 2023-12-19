control 'SV-209045' do
  title 'The system default umask for the csh shell must be 077.'
  desc 'The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.'
  desc 'check', 'Verify the "umask" setting is configured correctly in the "/etc/csh.cshrc" file by running the following command: 

# grep "umask" /etc/csh.cshrc

All output must show the value of "umask" set to 077, as shown in the below: 

# grep "umask" /etc/csh.cshrc
umask 077

If the above command returns no output, or if the umask is configured incorrectly, this is a finding.'
  desc 'fix', 'To ensure the default umask for users of the C shell is set properly, add or correct the "umask" setting in "/etc/csh.cshrc" to read as follows: 

umask 077'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9298r357920_chk'
  tag severity: 'low'
  tag gid: 'V-209045'
  tag rid: 'SV-209045r793766_rule'
  tag stig_id: 'OL6-00-000343'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9298r357921_fix'
  tag 'documentable'
  tag legacy: ['SV-64879', 'V-50673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
