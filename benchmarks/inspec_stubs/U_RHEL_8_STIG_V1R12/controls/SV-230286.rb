control 'SV-230286' do
  title 'The RHEL 8 SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Verify the SSH public host key files have mode "0644" or less permissive with the following command:

$ sudo ls -l /etc/ssh/*.pub

-rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

If any key.pub file has a mode more permissive than "0644", this is a finding.

Note: SSH public key files may be found in other directories on the system depending on the installation.'
  desc 'fix', 'Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

$ sudo chmod 0644 /etc/ssh/*key.pub

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32955r567604_chk'
  tag severity: 'medium'
  tag gid: 'V-230286'
  tag rid: 'SV-230286r627750_rule'
  tag stig_id: 'RHEL-08-010480'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32930r567605_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
