control 'SV-251755' do
  title 'The NSX-T Tier-0 Gateway must be configured to have Internet Control Message Protocol (ICMP) redirects disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Redirect ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules, and choose each Tier-0 Gateway in the drop-down.

Review each Tier-0 Gateway Firewalls rules to verify one exists to drop ICMP redirects.

If a rule does not exist to drop ICMP redirects, this is a finding.'
  desc 'fix', 'To configure a shared rule to drop ICMP unreachable messages do the following:

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> All Shared Rules.

Click "Add Rule" (Add a policy first if needed), under services select "ICMP Redirect", and then click "Apply".

Enable logging, under the "Applied To" field select the target Tier-0 Gateways, and then click "Publish" to enforce the new rule.

Note: A rule can also be created under Gateway Specific Rules to meet this requirement.'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55192r810147_chk'
  tag severity: 'medium'
  tag gid: 'V-251755'
  tag rid: 'SV-251755r810149_rule'
  tag stig_id: 'T0RT-3X-000066'
  tag gtitle: 'SRG-NET-000362-RTR-000115'
  tag fix_id: 'F-55146r810148_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
