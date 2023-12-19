control 'SV-102369' do
  title 'The SEL-2740S must be configured with backup flows for all host and switch flows to ensure proper failover scheme is in place for the network.'
  desc 'The SEL-2740S must be capable of multiple fast failover, backup and in cases isolation of the traffic from a detected threat in the system.'
  desc 'check', 'Review the SEL-2740S flow rules to ensure each flow has a Fast Failover Group configured.

If the switch is not configured to provide backup flows, this is a finding.'
  desc 'fix', 'To configure a Fast Failover Group for a given flow, do the following:

1. Log on to OTSDN Controller using Permission Level 3.
2. Under Group Entry General settings, select "Group ID" and "Group Type" as "Fast Failover".
3. Select appropriate number of Action Buckets dependent upon use case.
4. Determine valid watch port or group, and select supported actions.
5. Click "Submit".'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch L2S'
  tag check_id: 'C-91579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92281'
  tag rid: 'SV-102369r1_rule'
  tag stig_id: 'SELS-SW-000300'
  tag gtitle: 'SRG-NET-000512-L2S-000030'
  tag fix_id: 'F-98521r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
