control 'SV-251736' do
  title 'The NSX-T Tier-0 Gateway Firewall must not have any unpublished firewall policies or rules.'
  desc 'Unpublished firewall rules may be enabled inadvertently and cause unintended filtering or introduce unvetted/unauthorized traffic flows.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode and no stateless rules exist, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-0 Gateway, ensure there are no Unpublished changes.

If there is a message for Total Unpublished Changes and Publish is not greyed out, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules.

For each Tier-0 Gateway with Unpublished changes, review any unpublished changes and click either "Revert" or "Publish".'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway Firewall'
  tag check_id: 'C-55173r810073_chk'
  tag severity: 'high'
  tag gid: 'V-251736'
  tag rid: 'SV-251736r810075_rule'
  tag stig_id: 'T0FW-3X-000002'
  tag gtitle: 'SRG-NET-000019-FW-000004'
  tag fix_id: 'F-55127r810074_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
