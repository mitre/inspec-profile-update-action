control 'SV-215329' do
  title 'The AIX ldd command must be disabled.'
  desc 'The ldd command provides a list of dependent libraries needed by a given binary, which is useful for troubleshooting software. Instead of parsing the binary file, some ldd implementations invoke the program with a special environment variable set, which causes the system dynamic linker to display the list of libraries. Specially crafted binaries can specify an alternate dynamic linker which may cause a program to be executed instead of examined. If the program is from an untrusted source, such as in a user home directory, or a file suspected of involvement in a system compromise, unauthorized software may be executed with the rights of the user running ldd.'
  desc 'check', %q(Consult vendor documentation concerning the "ldd" command. 

If the command provides protection from the execution of untrusted executables, this is not a finding. 

Determine the location of the system's "ldd" command:
# find / -name ldd 

If no file exists, this is not a finding. 

Check the permissions of the found "ldd" file: 

# ls -lL <path to ldd> 
----------    1 bin      bin            6289 Feb 28 2017  /usr/bin/ldd

If the file mode of the file is more permissive than "0000", this is a finding)
  desc 'fix', 'Disable the "ldd" command by removing its permissions using command:
# chmod 0000 <path to ldd>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16527r294438_chk'
  tag severity: 'medium'
  tag gid: 'V-215329'
  tag rid: 'SV-215329r508663_rule'
  tag stig_id: 'AIX7-00-003016'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16525r294439_fix'
  tag 'documentable'
  tag legacy: ['V-91619', 'SV-101717']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
