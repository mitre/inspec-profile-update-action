control 'SV-38455' do
  title 'All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with that GID is subsequently created, the user may have unintended rights to the group.'
  desc 'fix', 'Add a group to the system (edit /etc/group) for each GID referenced without a corresponding group.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-781'
  tag rid: 'SV-38455r1_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'GEN000380'
  tag fix_id: 'F-31511r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
