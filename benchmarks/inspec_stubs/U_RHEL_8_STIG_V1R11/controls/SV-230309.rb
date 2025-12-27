control 'SV-230309' do
  title 'Local RHEL 8 initialization files must not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  desc 'check', 'Verify that local initialization files do not execute world-writable programs.

Check the system for world-writable files.

The following command will discover and print world-writable files. Run it once for each local partition [PART]: 

$ sudo find [PART] -xdev -type f -perm -0002 -print

For all files listed, check for their presence in the local initialization files with the following commands:

Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

$ sudo grep <file> /home/*/.*

If any local initialization files are found to reference world-writable files, this is a finding.'
  desc 'fix', 'Set the mode on files being executed by the local initialization files with the following command:

$ sudo chmod 0755 <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32978r567673_chk'
  tag severity: 'medium'
  tag gid: 'V-230309'
  tag rid: 'SV-230309r627750_rule'
  tag stig_id: 'RHEL-08-010660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32953r567674_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
