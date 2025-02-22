control 'SV-29540' do
  title 'The ldd command must be disabled unless it protects against the execution of untrusted files.'
  desc 'The ldd command provides a list of dependent libraries needed by a given binary, which is useful for troubleshooting software. Instead of parsing the binary file, some ldd implementations invoke the program with a special environment variable set, which causes the system dynamic linker to display the list of libraries. Specially crafted binaries can specify an alternate dynamic linker which may cause a program to be executed instead of examined. If the program is from an untrusted source, such as in a user home directory, or a file suspected of involvement in a system compromise, unauthorized software may be executed with the rights of the user running ldd. 

Some ldd implementations include protections preventing the execution of untrusted files. If such protections exist, this requirement is not applicable.

An acceptable method of disabling ldd is changing its mode to 0000. The SA may conduct troubleshooting by temporarily changing the mode to allow execution and running the ldd command as an unprivileged user upon trusted system binaries.'
  desc 'check', "Determine if the system's ldd executable exists and is executable.
# ls -lL /usr/ccs/bin/ldd

If the file exists and has any execute permissions, this is a finding."
  desc 'fix', 'Remove the execute permissions from the ldd executable.
# chmod a-x /usr/ccs/bin/ldd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-30036r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23953'
  tag rid: 'SV-29540r1_rule'
  tag stig_id: 'GEN007960'
  tag gtitle: 'GEN007960'
  tag fix_id: 'F-26870r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
