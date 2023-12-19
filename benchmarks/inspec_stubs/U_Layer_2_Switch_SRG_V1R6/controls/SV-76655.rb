control 'SV-76655' do
  title 'The layer 2 switch must be configured to fail securely in the event of an operational failure.'
  desc 'If the switch fails in an unsecure manner (open), unauthorized traffic originating externally to the enclave may enter or the device may permit unauthorized information release. Fail secure is a condition achieved by employing information system mechanisms to ensure, in the event of an operational failure of the switch, that it does not enter into an unsecure state where intended security properties no longer hold.

If the device fails, it must not fail in a manner that will allow unauthorized access. If the switch fails for any reason, it must stop forwarding traffic altogether or maintain the configured security policies. If the device stops forwarding traffic, maintaining network availability would be achieved through device redundancy.


An example is a firewall that blocks all traffic rather than allowing all traffic when a firewall component fails (e.g., fail closed and do not forward traffic). This prevents an attacker from forcing a failure of the system in order to obtain access. Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Review the vendor documentation to determine if the layer 2 switch will fail to a secure state in the event that the system initialization fails, shutdown fails, or abort fails.

If the layer 2 switch does not fail to a secure state in the event that the system initialization fails, shutdown fails, or abort fails, this is a finding.'
  desc 'fix', 'Configure the layer 2 switch to fail to a secure state upon failure of initialization, shutdown, or abort actions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62165'
  tag rid: 'SV-76655r2_rule'
  tag stig_id: 'SRG-NET-000235-L2S-000031'
  tag gtitle: 'SRG-NET-000235'
  tag fix_id: 'F-68085r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']
end
