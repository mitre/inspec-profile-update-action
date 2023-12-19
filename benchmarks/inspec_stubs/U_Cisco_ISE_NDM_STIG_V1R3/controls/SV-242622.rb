control 'SV-242622' do
  title 'The Cisco ISE must generate audit records when successful attempts to delete administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Verify logging categories have been configured to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Administrative and Operational Audit (INFO severity category) and AAA Audit (WARNING severity level) have been configured and set to the syslog target.

If the Administrative and Operational Audit (INFO severity) and the AAA Audit (WARNING) logging category are not configured to send to the central syslog server, this is a finding.'
  desc 'fix', 'Enable logging categories for Cisco ISE to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Click the radio button next to the Administrative and Operational Audit logging category and then click "Edit".
3. Choose INFO from the Log Severity Level drop-down list.
4. In the Targets field, move the syslog target name that is being used to the Selected box.
5. Repeat steps 2 and 3 with the selection of AAA Audit with the WARNING severity code.
6. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45897r714174_chk'
  tag severity: 'medium'
  tag gid: 'V-242622'
  tag rid: 'SV-242622r714176_rule'
  tag stig_id: 'CSCO-NM-000160'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-45854r714175_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
