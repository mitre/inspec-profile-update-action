control 'SV-220346' do
  title 'MarkLogic Server must be able to generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc "Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

MarkLogic Server includes an auditing capability. Auditing can be enabled to capture security-relevant events to monitor suspicious database activity or to satisfy applicable auditing requirements. The generation of audit events can be configured by including or excluding MarkLogic Server roles, users, or documents based on URI. Some actions that can be audited are the following:
- Startup and shutdown of MarkLogic Server
- Adding or removing roles from a user
- Usage of amps
- Starting and stopping the auditing system

For the complete list of auditable events and their descriptions, see Auditing Events in the Administrator's Guide:
https://docs.marklogic.com/guide/admin/auditing"
  desc 'check', 'If MarkLogic is currently required to audit the retrieval of privilege/permission/role membership information, check the MarkLogic security and audit configurations to verify audit records are produced when the DBMS denies retrieval of privileges/permissions/role membership.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means there is no auditing and this is a finding. 
5. If audit enabled field is true, but the security-access audit event is not selected, this is a finding.
6. If security-access audit event is selected, but "successful events only" is selected in the outcome setting of the audit restrictions is selected, this is a finding.'
  desc 'fix', 'If MarkLogic is currently required to audit the retrieval of privilege/permission/role membership information, change the MarkLogic security and audit configurations to ensure audit records are produced when the DBMS denies retrieval of privileges/permissions/role membership.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the security-access audit event.
6. Enable "both" under the outcome setting in the audit restrictions section.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22061r401489_chk'
  tag severity: 'medium'
  tag gid: 'V-220346'
  tag rid: 'SV-220346r622777_rule'
  tag stig_id: 'ML09-00-000750'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-22050r401490_fix'
  tag 'documentable'
  tag legacy: ['SV-110039', 'V-100935']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
