control 'SV-207171' do
  title 'The router must be configured to fail securely in the event of an operational failure.'
  desc 'If the router fails in an unsecure manner (open), unauthorized traffic originating externally to the enclave may enter or the device may permit unauthorized information release. Fail secure is a condition achieved by employing information system mechanisms to ensure, in the event of an operational failure of the router, that it does not enter into an unsecure state where intended security properties no longer hold.

If the device fails, it must not fail in a manner that will allow unauthorized access. If the router fails for any reason, it must stop forwarding traffic altogether or maintain the configured security policies. If the device stops forwarding traffic, maintaining network availability would be achieved through device redundancy.'
  desc 'check', 'Review the documentation of the router or interview the System Administrator.

Verify that the router fails securely in the event of an operational failure.

If it cannot fail securely, this is a finding.'
  desc 'fix', 'This is a capability that would be intrinsic to the router as a result of its development and may not be configurable.

If it is a configurable option, configure the device to fail securely in the event of an operational failure.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7432r382541_chk'
  tag severity: 'medium'
  tag gid: 'V-207171'
  tag rid: 'SV-207171r604135_rule'
  tag stig_id: 'SRG-NET-000365-RTR-000112'
  tag gtitle: 'SRG-NET-000365'
  tag fix_id: 'F-7432r382542_fix'
  tag 'documentable'
  tag legacy: ['V-55789', 'SV-70043']
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']
end
