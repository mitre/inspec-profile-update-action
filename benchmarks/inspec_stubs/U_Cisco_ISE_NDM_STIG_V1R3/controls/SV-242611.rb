control 'SV-242611' do
  title 'For the local web-based account of last resort, the Cisco ISE must automatically audit account disabling actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
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
  tag check_id: 'C-45886r714141_chk'
  tag severity: 'medium'
  tag gid: 'V-242611'
  tag rid: 'SV-242611r714143_rule'
  tag stig_id: 'CSCO-NM-000050'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-45843r714142_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
