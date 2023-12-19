control 'SV-27069' do
  title 'All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the same GID is subsequently created, the user may have unintended rights to the group.'
  desc 'fix', 'Add a group to the system for each GID referenced that does not have a corresponding group. 

#/usr/sbin/groupadd < group >'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-781'
  tag rid: 'SV-27069r1_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'GEN000380'
  tag fix_id: 'F-33975r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
