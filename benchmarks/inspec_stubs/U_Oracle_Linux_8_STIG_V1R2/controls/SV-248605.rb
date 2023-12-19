control 'SV-248605' do
  title "The OL 8 SSH daemon must not allow authentication using known host's authentication."
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow authentication using known host’s authentication with the following command: 
 
$ sudo grep -i IgnoreUserKnownHosts /etc/ssh/sshd_config 
 
IgnoreUserKnownHosts yes 
 
If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow authentication using known host’s authentication. 
 
Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes": 
 
IgnoreUserKnownHosts yes 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52039r779379_chk'
  tag severity: 'medium'
  tag gid: 'V-248605'
  tag rid: 'SV-248605r779381_rule'
  tag stig_id: 'OL08-00-010520'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51993r779380_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
