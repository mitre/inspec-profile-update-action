control 'SV-218211' do
  title 'All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file.'
  desc 'If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to the group.'
  desc 'check', 'Perform the following to ensure there are no GIDs referenced in /etc/passwd not defined in /etc/group:
# pwck -r
If GIDs referenced in /etc/passwd are not defined in /etc/group are returned, this is a finding.'
  desc 'fix', 'Add a group to the system for each GID referenced without a corresponding group.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19686r553970_chk'
  tag severity: 'low'
  tag gid: 'V-218211'
  tag rid: 'SV-218211r603259_rule'
  tag stig_id: 'GEN000380'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19684r553971_fix'
  tag 'documentable'
  tag legacy: ['V-781', 'SV-63319']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
