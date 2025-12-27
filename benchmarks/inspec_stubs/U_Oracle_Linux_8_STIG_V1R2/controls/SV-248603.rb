control 'SV-248603' do
  title 'The OL 8 SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc 'check', 'Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command: 
 
$ sudo grep -i strictmodes /etc/ssh/sshd_config 
 
StrictModes yes 
 
If "StrictModes" is set to "no" or is missing, or if the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to perform strict mode checking of home directory configuration files.  
 
Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" and set the value to "yes": 
 
StrictModes yes 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52037r779373_chk'
  tag severity: 'medium'
  tag gid: 'V-248603'
  tag rid: 'SV-248603r779375_rule'
  tag stig_id: 'OL08-00-010500'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51991r779374_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
