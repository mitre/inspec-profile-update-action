control 'SV-217177' do
  title 'All SUSE operating system local initialization files must not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  desc 'check', %q(Verify that SUSE operating system local initialization files do not execute world-writable programs.

Check the system for world-writable files with the following command:

> sudo find / -xdev -perm -002 -type f -exec ls -ld {} \;

For all files listed, check for their presence in the local
initialization files with the following command:

Note: The example will be for a system that is configured to create
users' home directories in the "/home" directory.

> sudo find /home/* -maxdepth 1 -type f -name \.\* -exec grep -H <file> {} \;

If any local initialization files are found to reference world-writable files, this is a finding.)
  desc 'fix', 'Remove the references to these files in the local initialization scripts or remove the world-writable permission of files referenced by SUSE operating system local initialization scripts with the following command:

> sudo chmod 0755 <file>'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18405r646729_chk'
  tag severity: 'medium'
  tag gid: 'V-217177'
  tag rid: 'SV-217177r646731_rule'
  tag stig_id: 'SLES-12-010780'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18403r646730_fix'
  tag 'documentable'
  tag legacy: ['SV-91921', 'V-77225']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
