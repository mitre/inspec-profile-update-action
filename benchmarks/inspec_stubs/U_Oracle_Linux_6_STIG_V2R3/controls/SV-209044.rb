control 'SV-209044' do
  title 'The system default umask for the bash shell must be 077.'
  desc 'The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.'
  desc 'check', 'Verify the "umask" setting is configured correctly in the "/etc/bashrc" file by running the following command: 

# grep "umask" /etc/bashrc

All output must show the value of "umask" set to 077, as shown below: 

# grep "umask" /etc/bashrc
umask 077
umask 077

If the above command returns no output, or if the umask is configured incorrectly, this is a finding.'
  desc 'fix', 'To ensure the default umask for users of the Bash shell is set properly, add or correct the "umask" setting in "/etc/bashrc" to read as follows: 

umask 077'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9297r357917_chk'
  tag severity: 'low'
  tag gid: 'V-209044'
  tag rid: 'SV-209044r603263_rule'
  tag stig_id: 'OL6-00-000342'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9297r357918_fix'
  tag 'documentable'
  tag legacy: ['SV-64913', 'V-50707']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
