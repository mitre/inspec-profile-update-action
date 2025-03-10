control 'SV-242610' do
  title 'For the local web-based account of last resort and the default local CLI account, the Cisco ISE must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
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
  tag check_id: 'C-45885r714138_chk'
  tag severity: 'medium'
  tag gid: 'V-242610'
  tag rid: 'SV-242610r879526_rule'
  tag stig_id: 'CSCO-NM-000040'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-45842r714139_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
