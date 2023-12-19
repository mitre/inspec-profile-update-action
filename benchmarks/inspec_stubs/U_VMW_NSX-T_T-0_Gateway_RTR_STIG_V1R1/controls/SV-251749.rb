control 'SV-251749' do
  title 'The NSX-T Tier-0 Gateway must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the router, the key component used to build forwarding paths, and is also instrumental with all network management functions. Hence, any disruption or DoS attack to the route processor can result in mission critical network outages.'
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and choose each Tier-0 Gateway in the drop-down.

Review each Tier-0 Gateway Firewalls rules to verify rules exist to restrict traffic to itself.

If a rule or rules do not exist to restrict traffic to external interface IPs, this is a finding.'
  desc 'fix', 'To configure firewall rule(s) to restrict traffic destined to interfaces on a Tier-0 Gateway do the following:

From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and select the target Tier-0 Gateway from the drop-down.

Click "Add Rule" (Add a policy first if needed) and configure the destinations to include all IPs for external interfaces.

Update the action to "Drop" or "Reject".

Enable logging, then under the "Applied To" field, select the target Tier-0 Gateways and click "Publish" to enforce the new rule.

Other rules may be constructed to allow traffic to external interface IPs if required above this default deny rule.'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55186r810129_chk'
  tag severity: 'high'
  tag gid: 'V-251749'
  tag rid: 'SV-251749r810131_rule'
  tag stig_id: 'T0RT-3X-000038'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-55140r810130_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
