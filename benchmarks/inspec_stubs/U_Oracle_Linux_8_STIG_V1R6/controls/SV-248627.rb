control 'SV-248627' do
  title 'Local OL 8 initialization files must not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  desc 'check', %q(Verify that local initialization files do not execute world-writable programs. 
 
Check the system for world-writable files. 
 
The following command will discover and print world-writable files. Run it once for each local partition [PART]: 
 
$ sudo find [PART] -xdev -type f -perm -0002 -print 
 
For all files listed, check for their presence in the local initialization files with the following commands: 
 
Note: The example will be for a system that is configured to create users' home directories in the "/home" directory. 
 
$ sudo grep <file> /home/*/.* 
 
If any local initialization files are found to reference world-writable files, this is a finding.)
  desc 'fix', 'Set the mode on files being executed by the local initialization files with the following command: 
 
$ sudo chmod 0755 <file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52061r779445_chk'
  tag severity: 'medium'
  tag gid: 'V-248627'
  tag rid: 'SV-248627r779447_rule'
  tag stig_id: 'OL08-00-010660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52015r779446_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
