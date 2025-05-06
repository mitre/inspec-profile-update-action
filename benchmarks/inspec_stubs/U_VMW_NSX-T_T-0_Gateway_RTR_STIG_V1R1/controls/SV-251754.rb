control 'SV-251754' do
  title 'The NSX-T Tier-0 Gateway must be configured to have Internet Control Message Protocol (ICMP) mask replies disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules, and choose each Tier-0 Gateway in the drop-down.

Review each Tier-0 Gateway Firewall rule to verify one exists to drop ICMP mask replies.

If a rule does not exist to drop ICMP mask replies, this is a finding.'
  desc 'fix', 'To configure a shared rule to drop ICMP unreachable messages do the following:

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> All Shared Rules.

Click "Add Rule" (Add a policy first if needed), under "Services" select the custom service that identifies ICMP mask replies, and then click "Apply".

Enable logging, under the "Applied To" field select the target Tier-0 Gateways, and then click "Publish" to enforce the new rule.

Note: A rule can also be created under Gateway Specific Rules to meet this requirement.

Note: A pre-created service for ICMP mask replies does not exist by default and may need to be created.'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55191r810144_chk'
  tag severity: 'medium'
  tag gid: 'V-251754'
  tag rid: 'SV-251754r810146_rule'
  tag stig_id: 'T0RT-3X-000065'
  tag gtitle: 'SRG-NET-000362-RTR-000114'
  tag fix_id: 'F-55145r810145_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
