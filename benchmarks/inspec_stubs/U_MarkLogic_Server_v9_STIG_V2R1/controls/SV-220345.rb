control 'SV-220345' do
  title 'MarkLogic Server must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
  desc 'check', 'Check the MarkLogic security and audit configurations to verify that audit records are produced when privileges/permissions/role memberships are retrieved, if they are required by the system documentation or organizational policies.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means there is no auditing and this is a finding. 
5. If audit enabled field is true, but the security-access audit event is not selected, this is a finding.
6. If security-access audit event is selected, but "failed events only" is selected in the outcome setting of the audit restrictions is selected, this is a finding.'
  desc 'fix', 'Change the MarkLogic security and audit configurations to ensure audit records are produced when privileges/permissions/role memberships are retrieved, if they are required by the system documentation or organizational policies.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the security-access audit event.
6. Enable "both" under the outcome setting in the audit restrictions section.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22060r401486_chk'
  tag severity: 'medium'
  tag gid: 'V-220345'
  tag rid: 'SV-220345r622777_rule'
  tag stig_id: 'ML09-00-000700'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-22049r401487_fix'
  tag 'documentable'
  tag legacy: ['SV-110037', 'V-100933']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
