control 'SV-251768' do
  title 'The NSX-T Tier-1 Gateway Firewall must apply ingress filters to traffic that is inbound to the network through any active external interface.'
  desc 'Unrestricted traffic to the trusted networks may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Firewall filters control the flow of network traffic and ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the internet) must be kept separated.'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules. Choose each Tier-1 Gateway in the drop-down and review the firewall rules "Applied To" field to verify no rules are selectively applied to interfaces instead of the Gateway Firewall entity.

If any Gateway Firewall rules are applied to individual interfaces, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules and choose the target Tier-1 Gateway from the drop-down.

For any rules that have individual interfaces specified in the "Applied To" field, click "Edit" on the "Applied To" column and remove the interfaces selected, leaving only the Tier-1 Gateway object type checked.

Click "Publish" to save any rule changes.'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier 1 Gateway Firewall'
  tag check_id: 'C-55205r810197_chk'
  tag severity: 'medium'
  tag gid: 'V-251768'
  tag rid: 'SV-251768r810199_rule'
  tag stig_id: 'T1FW-3X-000030'
  tag gtitle: 'SRG-NET-000364-FW-000031'
  tag fix_id: 'F-55159r810198_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
