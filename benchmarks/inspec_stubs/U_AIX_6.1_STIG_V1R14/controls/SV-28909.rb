control 'SV-28909' do
  title 'The ldd command must be disabled unless it protects against the execution of untrusted files.'
  desc 'The ldd command provides a list of dependent libraries needed by a given binary, which is useful for troubleshooting software.  Instead of parsing the binary file, some ldd implementations invoke the program with a special environment variable set, which causes the system dynamic linker to display the list of libraries.  Specially crafted binaries can specify an alternate dynamic linker which may cause a program to be executed instead of examined.  If the program is from an untrusted source, such as in a user home directory, or a file suspected of involvement in a system compromise, unauthorized software may be executed with the rights of the user running ldd.  

Some ldd implementations include protections preventing the execution of untrusted files.  If such protections exist, this requirement is not applicable.

An acceptable method of disabling ldd is changing its mode to 0000.  The SA may conduct troubleshooting by temporarily changing the mode to allow execution and running the ldd command as an unprivileged user upon trusted system binaries.'
  desc 'check', "Consult vendor documentation concerning the ldd command.  If the command provides protection from the execution of untrusted executables, this is not a finding.

Determine the location of the system's ldd command.
Procedure:
# find / -name ldd
If no file exists, this is not a finding.

Check the permissions of the found ldd file.
# ls -lL <path to ldd>

If the file mode of the file is more permissive than 0000, this is a finding."
  desc 'fix', 'Disable the ldd command by removing its permissions.

Procedure:
# chmod 0000 <path to ldd>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-30816r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23953'
  tag rid: 'SV-28909r1_rule'
  tag stig_id: 'GEN007960'
  tag gtitle: 'GEN007960'
  tag fix_id: 'F-27397r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
