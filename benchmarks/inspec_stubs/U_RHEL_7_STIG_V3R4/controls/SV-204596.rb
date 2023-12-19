control 'SV-204596' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH public host key files have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', %q(Verify the SSH public host key files have mode "0644" or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

The following command will find all SSH public key files on the system:

# find /etc/ssh -name '*.pub' -exec ls -lL {} \;

-rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

If any file has a mode more permissive than "0644", this is a finding.)
  desc 'fix', 'Note: SSH public key files may be found in other directories on the system depending on the installation. 

Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

# chmod 0644 /etc/ssh/*.key.pub'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4720r88980_chk'
  tag severity: 'medium'
  tag gid: 'V-204596'
  tag rid: 'SV-204596r603261_rule'
  tag stig_id: 'RHEL-07-040410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4720r88981_fix'
  tag 'documentable'
  tag legacy: ['V-72255', 'SV-86879']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
