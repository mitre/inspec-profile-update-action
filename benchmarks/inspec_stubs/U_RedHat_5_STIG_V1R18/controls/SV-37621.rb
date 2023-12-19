control 'SV-37621' do
  title "The 'ldd' command must be disabled unless it protects against the execution of untrusted files."
  desc "The 'ldd' command provides a list of dependent libraries needed by a given binary, which is useful for troubleshooting software.  Instead of parsing the binary file, some 'ldd' implementations invoke the program with a special environment variable set, which causes the system dynamic linker to display the list of libraries.  Specially crafted binaries can specify an alternate dynamic linker which may cause a program to be executed instead of examined.  If the program is from an untrusted source, such as in a user home directory, or a file suspected of involvement in a system compromise, unauthorized software may be executed with the rights of the user running 'ldd'.  

Some 'ldd' implementations include protections that prevent the execution of untrusted files.  Recent RHEL 5 glibc RPMs also protect against the execution of untrusted files.  If such protections exist, this requirement is not applicable.

An acceptable method of disabling 'ldd' is changing its mode to 0000.  The SA may conduct troubleshooting by temporarily changing the mode to allow execution and running the 'ldd' command as an unprivileged user upon trusted system binaries."
  desc 'check', "Check the system for the 'ldd' binary.

Procedure:
# ls -lL /usr/bin/ldd

If the 'ldd' binary has any executable permissions bits set, this is a finding."
  desc 'fix', "Remove the execute permissions from the 'ldd' executable.

Procedure:
# chmod a-x /usr/bin/ldd"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36820r3_chk'
  tag severity: 'medium'
  tag gid: 'V-23953'
  tag rid: 'SV-37621r2_rule'
  tag stig_id: 'GEN007960'
  tag gtitle: 'GEN007960'
  tag fix_id: 'F-31658r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
