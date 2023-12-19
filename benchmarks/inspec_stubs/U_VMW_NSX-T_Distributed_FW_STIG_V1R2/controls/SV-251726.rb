control 'SV-251726' do
  title 'The NSX-T Distributed Firewall must not have any unpublished firewall policies or rules.'
  desc 'Unpublished firewall rules may be enabled inadvertently and cause unintended filtering or introduce unvetted/unauthorized traffic flows.'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Distributed Firewall >> Category Specific Rules.

If there is a message for Total Unpublished Changes and Publish is not greyed out, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Distributed Firewall >> Category Specific Rules.

Review any unpublished changes, and click either "Revert" or "Publish".'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Distributed Firewall'
  tag check_id: 'C-55163r810030_chk'
  tag severity: 'high'
  tag gid: 'V-251726'
  tag rid: 'SV-251726r810032_rule'
  tag stig_id: 'TDFW-3X-000002'
  tag gtitle: 'SRG-NET-000019-FW-000004'
  tag fix_id: 'F-55117r810031_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
