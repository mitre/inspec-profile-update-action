control 'SV-214908' do
  title 'All setuid executables on the macOS system must be documented.'
  desc 'Very few of the executables that come preinstalled on the macOS host have the "setuid" bit set, and administrators should never add the "setuid" bit to any executable that does not already have it set by the vendor. Executables with the "setuid" bit set allow anyone that executes them to be temporarily assigned the UID of the file owner. In practice, this almost always is the root account. While some vendors depend on this file attribute for proper operation, security problems can result if "setuid" is assigned to programs allowing reading and writing of files, or shell escapes, as this could lead to unprivileged users gaining privileged access to files and directories on the system.'
  desc 'check', 'If available, provide a list of "setuids" provided by a vendor. To list all of the files with the "setuid" bit set, run the following command to send all results to a file named "suidfilelist":

/usr/bin/sudo find / -perm -4000 -exec /bin/ls -ldb {} \\; > suidfilelist

If any of the files listed are not documented as needing to have the "setuid" bit set by the vendor, this is a finding.'
  desc 'fix', 'Document all of the files with the "setuid" bit set.

Remove any undocumented files.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16108r397296_chk'
  tag severity: 'medium'
  tag gid: 'V-214908'
  tag rid: 'SV-214908r609363_rule'
  tag stig_id: 'AOSX-13-001145'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16106r397297_fix'
  tag 'documentable'
  tag legacy: ['V-81695', 'SV-96409']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
