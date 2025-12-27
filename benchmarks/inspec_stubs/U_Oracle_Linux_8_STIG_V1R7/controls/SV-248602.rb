control 'SV-248602' do
  title 'The OL 8 SSH private host key files must have mode "0640" or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', 'Verify the SSH private host key files have mode "0640" or less permissive with the following command: 
 
     $ sudo ls -alL /etc/ssh/ssh_host*key 
 
     -rw-r----- 1 root wheel 668 Nov 28 06:43 ssh_host_dsa_key 
     -rw-r----- 1 root wheel 582 Nov 28 06:43 ssh_host_key 
     -rw-r----- 1 root wheel 887 Nov 28 06:43 ssh_host_rsa_key 
 
If any private host key file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure the mode of SSH private host key files under "/etc/ssh" to "0640" with the following command: 
 
     $ sudo chmod 0640 /etc/ssh/ssh_host*key 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52036r880539_chk'
  tag severity: 'medium'
  tag gid: 'V-248602'
  tag rid: 'SV-248602r880541_rule'
  tag stig_id: 'OL08-00-010490'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51990r880540_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
