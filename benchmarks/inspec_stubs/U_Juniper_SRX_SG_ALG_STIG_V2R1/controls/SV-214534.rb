control 'SV-214534' do
  title 'The Juniper SRX Services Gateway Firewall must be configured to fail securely in the event of an operational failure of the firewall filtering or boundary protection function.'
  desc 'If a boundary protection device fails in an unsecure manner (open), information external to the boundary protection device may enter, or the device may permit unauthorized information release.

Secure failure ensures when a boundary control device fails, all traffic will be subsequently denied.

Fail secure is a condition achieved by employing information system mechanisms to ensure in the event of operational failures of boundary protection devices at managed interfaces (e.g., routers, firewalls, guards, and application gateways residing on protected subnetworks commonly referred to as demilitarized zones), information systems do not enter into unsecure states where intended security properties no longer hold.'
  desc 'check', 'Request documentation of the architecture and Juniper SRX configuration. Verify the site has configured the SRX to fail closed, thus preventing traffic from flowing through without filtering and inspection.

If the site has not configured the SRX to fail closed, this is a finding.'
  desc 'fix', 'Implement and configure the Juniper SRX to fail closed, thus preventing traffic from flowing through without filtering and inspection. In case of failure, document a process for the Juniper SRX to be configured to fail closed. Redundancy should be implemented if failing closed has a mission impact.'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15740r297286_chk'
  tag severity: 'medium'
  tag gid: 'V-214534'
  tag rid: 'SV-214534r557389_rule'
  tag stig_id: 'JUSX-AG-000127'
  tag gtitle: 'SRG-NET-000365-ALG-000123'
  tag fix_id: 'F-15738r297287_fix'
  tag 'documentable'
  tag legacy: ['V-66333', 'SV-80823']
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']
end
