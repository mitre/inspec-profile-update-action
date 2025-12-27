control 'SV-221859' do
  title 'The Oracle Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', "Verify the SSH private host key files have mode 0640 or less permissive.

The following command will find all SSH private key files on the system and list their modes:

# find / -name '*ssh_host*key' | xargs ls -lL

-rw-r----- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
-rw-r----- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
-rw-r----- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

If any file has a mode more permissive than 0640, this is a finding."
  desc 'fix', 'Configure the mode of SSH private host key files under "/etc/ssh" to "0640" with the following command:

# chmod 0640 /path/to/file/ssh_host*key'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23574r419649_chk'
  tag severity: 'medium'
  tag gid: 'V-221859'
  tag rid: 'SV-221859r603260_rule'
  tag stig_id: 'OL07-00-040420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23563r419650_fix'
  tag 'documentable'
  tag legacy: ['V-99457', 'SV-108561']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
