control 'SV-242609' do
  title 'For the local web-based account of last resort, the Cisco ISE must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
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
  tag check_id: 'C-45884r714135_chk'
  tag severity: 'medium'
  tag gid: 'V-242609'
  tag rid: 'SV-242609r714137_rule'
  tag stig_id: 'CSCO-NM-000030'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-45841r714136_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
