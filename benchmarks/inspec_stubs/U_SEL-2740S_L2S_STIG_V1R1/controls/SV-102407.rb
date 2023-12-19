control 'SV-102407' do
  title 'The SEL-2740S must be configured to capture flows for real-time visualization tools.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.'
  desc 'check', 'Review the SEL-2740S flow rules to ensure they only include the specific copy rules for capturing ingress and egress flows only on the designated port(s).

Note: A span port can be created to capture based on Flows, ports, or combination.

If the SEL-2740S is configured with flows with wildcard or unnecessary packet forwarding rules, this is a finding.'
  desc 'fix', 'Add specific SEL-2740S flow rules for capturing a copy of packets for user sessions use OpenFlow ALL Groups.

To add an SEL-2740S Group, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Under "Group Entry" General settings, select "Group ID" and "Group Type". Use a unique group ID and use an ALL group to send the packet to more than one destination.
3. Select appropriate number of Action Buckets dependent upon use case.
4. Determine valid watch port or group, and select supported actions.
5. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92319'
  tag rid: 'SV-102407r1_rule'
  tag stig_id: 'SELS-SW-000080'
  tag gtitle: 'SRG-NET-000332-L2S-000002'
  tag fix_id: 'F-98557r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
