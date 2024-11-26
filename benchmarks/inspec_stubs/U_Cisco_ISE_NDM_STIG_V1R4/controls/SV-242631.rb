control 'SV-242631' do
  title 'The Cisco ISE must audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Verify logging categories have been configured to send auditable events to the syslog target.

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Verify the Administrative and Operational Audit is configured for the INFO log severity level.
3. Verify both the Administrative and Operational Audit  and the AAA Audit logging categories have been set to the syslog target.

If the Administrative and Operational Audit (INFO severity) and the AAA Audit logging category is not configured to send to the central syslog server, this is a finding.'
  desc 'fix', 'Enable logging categories for Cisco ISE to send auditable events to the syslog target. 

From the Web Admin portal:
1. Choose Administration >> System >> Logging >> Logging Categories.
2. Click the radio button next to the Administrative and Operational Audit logging category and then click "Edit".
3. Choose INFO from the Log Severity Level drop-down list.
4. In the Targets field, move the syslog target name that is being used to the Selected box.
5. Repeat the above steps to enable the AAA Audit logging category. However, this logging category has INFO as the default log severity level and cannot be changed.
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45906r864198_chk'
  tag severity: 'medium'
  tag gid: 'V-242631'
  tag rid: 'SV-242631r864200_rule'
  tag stig_id: 'CSCO-NM-000250'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-45863r864199_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end
