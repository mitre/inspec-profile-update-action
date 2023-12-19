control 'SV-56473' do
  title 'Separate domain accounts must be used to manage public facing servers from any domain accounts used to manage internal servers.'
  desc 'Public facing servers should be in DMZs with separate Active Directory forests.  If, because of operational necessity, this is not possible, lateral movement from these servers must be mitigated within the forest.  Having different domain accounts for administering domain joined public facing servers, from domain accounts used on internal servers, protects against an attacker’s lateral movement from a compromised public facing server.'
  desc 'check', 'If the domain does not have any public facing servers, this is NA.

Review the local Administrators group on public facing servers.  Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For public facing servers, the Domain Admins group must be replaced by a domain member server administrator group whose members are different from any used to manage internal servers.

If any domain accounts or groups used to manage internal servers are members of the local administrators group, this is a finding.'
  desc 'fix', 'If the domain does not have any public facing servers, this is NA.

Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For public facing servers, replace the Domain Admins group with a domain member server administrator group whose members are different from any used to manage internal servers.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-49398r4_chk'
  tag severity: 'medium'
  tag gid: 'V-43652'
  tag rid: 'SV-56473r2_rule'
  tag stig_id: 'AD.0013'
  tag gtitle: 'AD.0013'
  tag fix_id: 'F-49252r2_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
