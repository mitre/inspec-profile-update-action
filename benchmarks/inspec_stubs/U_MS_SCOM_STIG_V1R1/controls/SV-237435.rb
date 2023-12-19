control 'SV-237435' do
  title 'The Microsoft SCOM SNMP Monitoring in SCOM must use SNMP V3.'
  desc 'SNMP Versions 1 and 2 do not use a FIPS-validated Keyed-Hash message Authentication Code (HMAC). SCOM has the capability of monitoring all versions of SNMP. As such, SNMP 1 and 2 monitoring should only be done if the device being monitored does not support SNMP V3.'
  desc 'check', 'From the SCOM Console, select the Administration workspace.

Navigate to Run As Configuration and select Accounts.

Review all of the listed Accounts.

If any account is listed under the "Community String" type, this is a finding.'
  desc 'fix', 'Create SNMP V3 Run As accounts and use these to monitor network devices:

Note that for this to work, SNMP V3 must be set up on the network device being monitored and some of the configuration info for this account must be obtained from that device.

From the SCOM Operations Console, select the Administration workspace, expand Run As Configuration, and select Accounts. Right-click and choose "Create Run As accounts". Click "Next" at the first screen and in the Run As account type, choose SNMP V3 account. Give it an appropriate display name and complete the wizard supplying the relevant information from the monitored network device(s).'
  impact 0.3
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40654r643949_chk'
  tag severity: 'low'
  tag gid: 'V-237435'
  tag rid: 'SV-237435r643951_rule'
  tag stig_id: 'SCOM-IA-000001'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-40617r643950_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
