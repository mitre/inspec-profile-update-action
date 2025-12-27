control 'SV-227573' do
  title 'All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the same GID is subsequently created, the user may have unintended rights to the group.'
  desc 'check', %q(Perform the following to ensure there are no GIDs referenced in /etc/passwd not defined in /etc/group.
# logins -o | awk -F: '$3 == ""'
If any lines are returned, there are GIDs referenced in /etc/passwd that are not defined in /etc/group, this is a finding.)
  desc 'fix', 'Add a group to the system for each GID referenced that does not have a corresponding group. 

#/usr/sbin/groupadd < group >'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29735r488258_chk'
  tag severity: 'low'
  tag gid: 'V-227573'
  tag rid: 'SV-227573r603266_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29723r488259_fix'
  tag 'documentable'
  tag legacy: ['V-781', 'SV-27069']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
