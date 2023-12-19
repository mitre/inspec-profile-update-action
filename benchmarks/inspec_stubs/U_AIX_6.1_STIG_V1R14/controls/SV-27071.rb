control 'SV-27071' do
  title 'All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group that does not exist on the system, and a group with that GID is subsequently created, the user may have unintended rights to the group.'
  desc 'check', 'Perform the following to ensure there are no GIDs referenced in /etc/passwd not defined in /etc/group:
# usrck -n ALL
If GIDs referenced in /etc/passwd are not defined in /etc/group are returned, this is a finding.'
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group.  

# smitty mkgroup'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27988r1_chk'
  tag severity: 'low'
  tag gid: 'V-781'
  tag rid: 'SV-27071r1_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'GEN000380'
  tag fix_id: 'F-33340r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
