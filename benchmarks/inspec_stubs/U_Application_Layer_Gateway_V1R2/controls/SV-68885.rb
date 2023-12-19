control 'SV-68885' do
  title 'The ALG must fail securely in the event of an operational failure.'
  desc 'If a boundary protection device fails in an unsecure manner (open), information external to the boundary protection device may enter, or the device may permit unauthorized information release.

Secure failure ensures when a boundary control device fails, all traffic will be subsequently denied.

Fail secure is a condition achieved by employing information system mechanisms to ensure in the event of operational failures of boundary protection devices at managed interfaces (e.g., routers, firewalls, guards, and application gateways residing on protected subnetworks commonly referred to as demilitarized zones), information systems do not enter into unsecure states where intended security properties no longer hold.'
  desc 'check', 'Verify the ALG fails securely in the event of an operational failure.

If the ALG does not fail securely in the event of an operational failure, this is a finding.'
  desc 'fix', 'Configure the ALG to fail securely in the event of an operational failure.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54639'
  tag rid: 'SV-68885r1_rule'
  tag stig_id: 'SRG-NET-000365-ALG-000123'
  tag gtitle: 'SRG-NET-000365-ALG-000123'
  tag fix_id: 'F-59495r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']
end
