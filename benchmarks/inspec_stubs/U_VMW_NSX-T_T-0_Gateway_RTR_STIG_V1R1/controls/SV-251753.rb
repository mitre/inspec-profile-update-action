control 'SV-251753' do
  title 'The NSX-T Tier-0 Gateway must be configured to have Internet Control Message Protocol (ICMP) unreachable notifications disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules, and choose each Tier-0 Gateway in the drop-down.

Review each Tier-0 Gateway Firewall rule to verify one exists to drop ICMP unreachable messages.

If a rule does not exist to drop ICMP unreachable messages, this is a finding.'
  desc 'fix', 'To configure a shared rule to drop ICMP unreachable messages do the following:

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> All Shared Rules.

Click "Add Rule" (Add a policy first if needed), under services select "ICMP Destination Unreachable", and then click "Apply".

Enable logging, and under the Applied To field select the target Tier-0 Gateways. Click "Publish" to enforce the new rule.

Note: A rule can also be created under Gateway Specific Rules to meet this requirement.'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55190r810141_chk'
  tag severity: 'medium'
  tag gid: 'V-251753'
  tag rid: 'SV-251753r810143_rule'
  tag stig_id: 'T0RT-3X-000064'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag fix_id: 'F-55144r810142_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
