control 'SV-248601' do
  title 'The OL 8 SSH public host key files must have mode "0644" or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Verify the SSH public host key files have mode "0644" or less permissive with the following command: 
 
$ sudo ls -l /etc/ssh/*.pub 
 
-rw-r--r-- 1 root wheel 618 Nov 28 06:43 ssh_host_dsa_key.pub 
-rw-r--r-- 1 root wheel 347 Nov 28 06:43 ssh_host_key.pub 
-rw-r--r-- 1 root wheel 238 Nov 28 06:43 ssh_host_rsa_key.pub 
 
If any "key.pub" file has a mode more permissive than "0644", this is a finding. 
 
Note: SSH public key files may be found in other directories on the system depending on the installation.'
  desc 'fix', 'Change the mode of public host key files under "/etc/ssh" to "0644" with the following command: 
 
$ sudo chmod 0644 /etc/ssh/*key.pub 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52035r779367_chk'
  tag severity: 'medium'
  tag gid: 'V-248601'
  tag rid: 'SV-248601r779369_rule'
  tag stig_id: 'OL08-00-010480'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51989r779368_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
