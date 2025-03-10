control 'SV-206793' do
  title 'The Voice Video Endpoint supporting Command and Control (C2) communications must implement Multilevel Precedence and Preemption (MLPP) call disconnect to enable Routine, Priority, Immediate, Flash, and Flash Override.'
  desc 'Configuring the C2 Voice Video Endpoint to implement MLPP ensures vital high-level communication occurs regardless of environmental, geographical, and political conditions. When conditions require immediate discussion among high-level officials, the C2 communications systems must be capable of implementing MLPP.

The MLPP service allows properly validated users to place priority calls and when necessary, C2 users can preempt lower-priority phone calls. Precedence designates the priority level that is associated with a call and preemption designates the process of terminating lower-precedence calls currently using a Voice Video Endpoint. A call of higher precedence can be extended to or through the device. A validated C2 user can preempt calls to targeted stations when AS-SIP is fully implemented on the network or through fully subscribed time division multiplexing (TDM) trunks. This capability assures high-level personnel of communication to critical organizations and personnel during network stress situations, such as a national emergency or degraded network situations.'
  desc 'check', 'If the Voice Video Endpoint does not support C2 communications, this check procedure is Not Applicable.

Verify the Voice Video Endpoint supporting C2 communications implements MLPP call disconnect to enable Routine, Priority, Immediate, Flash, and Flash Override.

If the Voice Video Endpoint supporting C2 communications does not implement MLPP call disconnect to enable Routine, Priority, Immediate, Flash, and Flash Override, this is a finding. If the MLPP call disconnect is not configured for use, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint supporting C2 communications to implement MLPP call disconnect to enable Routine, Priority, Immediate, Flash, and Flash Override.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7049r363902_chk'
  tag severity: 'medium'
  tag gid: 'V-206793'
  tag rid: 'SV-206793r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00046'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7049r363903_fix'
  tag 'documentable'
  tag legacy: ['SV-81263', 'V-66773']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
