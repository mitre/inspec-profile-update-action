control 'SV-204597' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', %q(Verify the SSH private host key files have mode "0640" or less permissive.

The following command will find all SSH private key files on the system and list their modes:

# find / -name '*ssh_host*key' | xargs ls -lL

-rw-r----- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
-rw-r----- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
-rw-r----- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

If any file has a mode more permissive than "0640", this is a finding.)
  desc 'fix', 'Configure the mode of SSH private host key files under "/etc/ssh" to "0640" with the following command:

# chmod 0640 /path/to/file/ssh_host*key'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4721r88983_chk'
  tag severity: 'medium'
  tag gid: 'V-204597'
  tag rid: 'SV-204597r603261_rule'
  tag stig_id: 'RHEL-07-040420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4721r88984_fix'
  tag 'documentable'
  tag legacy: ['V-72257', 'SV-86881']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
