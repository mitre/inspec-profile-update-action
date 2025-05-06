control 'SV-242613' do
  title 'The Cisco ISE must automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and ISSO. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
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
  impact 0.3
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45888r714147_chk'
  tag severity: 'low'
  tag gid: 'V-242613'
  tag rid: 'SV-242613r714149_rule'
  tag stig_id: 'CSCO-NM-000070'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-45845r714148_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
