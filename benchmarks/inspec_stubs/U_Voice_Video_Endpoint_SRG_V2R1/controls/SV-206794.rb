control 'SV-206794' do
  title 'The Voice Video Endpoint supporting Command and Control (C2) communications must implement Assured Service Session Initiation Protocol (AS-SIP).'
  desc 'Configuring the C2 Voice Video Endpoint to implement MLPP ensures vital high-level communication occurs regardless of environmental, geographical, and political conditions. When conditions require immediate discussion among high-level officials, the C2 communications systems must be capable of implementing MLPP.

The MLPP service allows properly validated users to place priority calls and when necessary, C2 users can preempt lower-priority phone calls. Precedence designates the priority level that is associated with a call and preemption designates the process of terminating lower-precedence calls currently using a Voice Video Endpoint. A call of higher precedence can be extended to or through the device. A validated C2 user can preempt calls to targeted stations when AS-SIP is fully implemented on the network or through fully subscribed time division multiplexing (TDM) trunks. This capability assures high-level personnel of communication to critical organizations and personnel during network stress situations, such as a national emergency or degraded network situations.'
  desc 'check', 'If the Voice Video Endpoint does not support C2 communications, this check procedure is Not Applicable.

Verify the Voice Video Endpoint supporting C2 communications implements AS-SIP.

If the Voice Video Endpoint supporting C2 communications does not implement AS-SIP, this is a finding. If AS-SIP is not configured for use, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint supporting C2 communications to implement AS-SIP.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7050r363905_chk'
  tag severity: 'medium'
  tag gid: 'V-206794'
  tag rid: 'SV-206794r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00047'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7050r363906_fix'
  tag 'documentable'
  tag legacy: ['SV-81265', 'V-66775']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
