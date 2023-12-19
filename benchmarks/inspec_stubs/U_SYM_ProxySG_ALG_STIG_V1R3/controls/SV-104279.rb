control 'SV-104279' do
  title 'Symantec ProxySG must fail securely in the event of an operational failure.'
  desc 'If a boundary protection device fails in an unsecure manner (open), information external to the boundary protection device may enter, or the device may permit unauthorized information release.

Secure failure ensures that when a boundary control device fails, all traffic will be subsequently denied.

Fail secure is a condition achieved by employing information system mechanisms to ensure that in the event of operational failures of boundary protection devices at managed interfaces (e.g., routers, firewalls, guards, and application gateways residing on protected subnetworks commonly referred to as demilitarized zones), information systems do not enter into unsecure states where intended security properties no longer hold.

Depending on the deployment architecture, there are many configurations to check that are external to the ProxySG to ensure that an operational failure results in a secure state. With these external configurations in place, the ProxySG meets this requirement inherently. However, if a ProxySG hardware appliance is configured in a transparent, physically in-path manner, the check and fix on the ProxySG will apply.'
  desc 'check', 'Verify that the transparent, physically in-line hardware ProxySG appliance is configured to fail securely in the event of an operational failure.

1. Browse to Configuration >> Network >> Adapters >> Bridges. 
2. Select the appropriate bridge-pair (whichever is in use) and click "Edit". 
3. Verify that the "fail-closed" radio button is selected.

If the "fail-closed" radio button is not selected, this is a finding.'
  desc 'fix', 'Configure the transparent, physically in-line hardware ProxySG appliance to fail securely in the event of an operational failure.

1. Browse to Configuration >> Network >> Adapters >> Bridges.
2. Select the appropriate bridge-pair (whichever is in use) and click "Edit". 
3. Select the "fail-closed" radio button and click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94325'
  tag rid: 'SV-104279r1_rule'
  tag stig_id: 'SYMP-AG-000560'
  tag gtitle: 'SRG-NET-000365-ALG-000123'
  tag fix_id: 'F-100441r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001126']
  tag nist: ['SC-7 (18)']
end
