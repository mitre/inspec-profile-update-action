control 'SV-246924' do
  title 'ONTAP must terminate shared/group account credentials when members leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', 'Use "security login show" to see all configured users and groups in ONTAP.

Use AD cmdlet "Get-ADGroupMember -Identity <identity>" to find the member to be removed from the ONTAP group.

If Active Directory does not terminate shared/group account credentials when members leave the group to prevent access to ONTAP, this is a finding.'
  desc 'fix', 'Use AD cmdlet "Remove-ADGroupMember -Identity <identity> -Members <member>" to remove a member from an ONTAP group.

Use AD cmdlet "Get-ADGroupMember -Identity <identity>" to see the member was removed from the ONTAP group.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50356r769102_chk'
  tag severity: 'medium'
  tag gid: 'V-246924'
  tag rid: 'SV-246924r769104_rule'
  tag stig_id: 'NAOT-AC-000003'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-50310r769103_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end
