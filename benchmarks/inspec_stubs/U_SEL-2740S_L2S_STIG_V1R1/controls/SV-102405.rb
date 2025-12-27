control 'SV-102405' do
  title 'The SEL-2740S must be configured to packet capture flows.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network. Session audits may include port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Review the SEL-2740S flow rules to ensure they only include the specific copy rules for capturing ingress and egress flows only on the designated port(s).

Note: A span port can be created to capture based on Flows, ports, or combination.

If the SEL-2740S is configured with flows with wildcard or unnecessary packet forwarding rules, this is a finding.'
  desc 'fix', 'Add specific SEL-2740S flow rules for capturing a copy of packets for user sessions use OpenFlow ALL Groups.

To add an SEL-2740S Group, do the following:
1. Log on to OTSDN Controller using Permission Level 3.
2. Under "Group Entry" General Settings, select "Group ID" and "Group Type".
3. Select appropriate number of Action Buckets dependent upon use case.
4. Determine valid watch port or group, and select supported actions.
5. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92317'
  tag rid: 'SV-102405r1_rule'
  tag stig_id: 'SELS-SW-000070'
  tag gtitle: 'SRG-NET-000331-L2S-000001'
  tag fix_id: 'F-98555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
