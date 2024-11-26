control 'SV-781' do
  title 'All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with that GID is subsequently created, the user may have unintended rights to that group.'
  desc 'check', 'List the primary group GIDs for all user accounts on the system. If these GIDs do not correspond to any groups defined on the system, this is a finding.'
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-281r2_chk'
  tag severity: 'low'
  tag gid: 'V-781'
  tag rid: 'SV-781r2_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'GEN000380'
  tag fix_id: 'F-935r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
