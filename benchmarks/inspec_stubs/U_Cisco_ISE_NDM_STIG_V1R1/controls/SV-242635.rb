control 'SV-242635' do
  title 'The Cisco ISE local uses must use role-based access control and role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.

The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
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
  tag check_id: 'C-45910r714213_chk'
  tag severity: 'medium'
  tag gid: 'V-242635'
  tag rid: 'SV-242635r714215_rule'
  tag stig_id: 'CSCO-NM-000290'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-45867r714214_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end
