control 'SV-44827' do
  title 'All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to the group.'
  desc 'check', 'Perform the following to ensure there are no GIDs referenced in /etc/passwd not defined in /etc/group:
# pwck -r
If GIDs referenced in /etc/passwd are not defined in /etc/group are returned, this is a finding.'
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42299r1_chk'
  tag severity: 'low'
  tag gid: 'V-781'
  tag rid: 'SV-44827r1_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'GEN000380'
  tag fix_id: 'F-38266r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
