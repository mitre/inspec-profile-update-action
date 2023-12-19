control 'SV-242612' do
  title 'For the local account of last resort, the Cisco ISE must automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Verify logging categories for Administrative and Operational Audit has been configured to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Administrative and Operational Audit has been set to INFO and the Targets field has been set to the syslog target.

If the Administrative and Operational Audit logging category is not configured for INFO severity level and send to the central syslog server, this is a finding.'
  desc 'fix', 'Enable logging categories for Cisco ISE to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Click the radio button next to the Administrative and Operational Audit logging category and then click "Edit".
3. Choose INFO from the Log Severity Level drop-down list.
4. In the Targets field, move the syslog target name that is being used to the Selected box.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45887r714144_chk'
  tag severity: 'medium'
  tag gid: 'V-242612'
  tag rid: 'SV-242612r714146_rule'
  tag stig_id: 'CSCO-NM-000060'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-45844r714145_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
