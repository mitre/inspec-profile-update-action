control 'SV-221739' do
  title 'The Oracle Linux operating system must be configured so that local initialization files do not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  desc 'check', %q(Verify that local initialization files do not execute world-writable programs.

Check the system for world-writable files with the following command:

# find / -xdev -perm -002 -type f -exec ls -ld {} \; | more

For all files listed, check for their presence in the local initialization files with the following commands:

Note: The example will be for a system that is configured to create users' home directories in the "/home" directory.

# grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files, this is a finding.)
  desc 'fix', 'Set the mode on files being executed by the local initialization files with the following command:

# chmod 0755 <file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23454r419289_chk'
  tag severity: 'medium'
  tag gid: 'V-221739'
  tag rid: 'SV-221739r603260_rule'
  tag stig_id: 'OL07-00-020730'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23443r419290_fix'
  tag 'documentable'
  tag legacy: ['V-99217', 'SV-108321']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
