control 'SV-44912' do
  title 'The root account must not have world-writable directories in its executable search path.'
  desc "If the root search path contains a world-writable directory, malicious software could be placed in the path by intruders and/or malicious users and inadvertently run by root with all of root's privileges."
  desc 'check', %q(Check for world-writable permissions on all directories in the root user's executable search path.

Procedure:
# ls -ld `echo $PATH | sed "s/:/ /g"`

If any of the directories in the PATH variable are world-writable, this is a finding.)
  desc 'fix', "For each world-writable path in root's executable search path, do one of the following:

1. Remove the world-writable permission on the directory.
Procedure:
# chmod o-w <path>

2. Remove the world-writable directory from the executable search path.
Procedure:
Identify and edit the initialization file referencing the world-writable directory and remove it from the PATH variable."
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42353r1_chk'
  tag severity: 'medium'
  tag gid: 'V-777'
  tag rid: 'SV-44912r1_rule'
  tag stig_id: 'GEN000960'
  tag gtitle: 'GEN000960'
  tag fix_id: 'F-38344r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
