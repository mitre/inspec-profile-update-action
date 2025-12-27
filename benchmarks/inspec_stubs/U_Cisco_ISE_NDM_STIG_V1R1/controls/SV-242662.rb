control 'SV-242662' do
  title 'The Cisco ISE must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
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
  tag check_id: 'C-45937r714294_chk'
  tag severity: 'medium'
  tag gid: 'V-242662'
  tag rid: 'SV-242662r714296_rule'
  tag stig_id: 'CSCO-NM-000650'
  tag gtitle: 'SRG-APP-000092-NDM-000224'
  tag fix_id: 'F-45894r714295_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
