control 'SV-220344' do
  title 'MarkLogic Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log, and can make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

MarkLogic Server includes an auditing capability. Auditing can be enabled to capture security-relevant events to monitor suspicious database activity or to satisfy applicable auditing requirements. The generation of audit events can be configured by including or excluding MarkLogic Server roles, users, or documents based on URI. Some actions that can be audited are the following:
- Startup and shutdown of MarkLogic Server
- Adding or removing roles from a user
- Usage of amps
- Starting and stopping the auditing system

For the complete list of auditable events and their descriptions, see Auditing Events in the Administrator's Guide:
https://docs.marklogic.com/guide/admin/auditing"
  desc 'check', 'Check MarkLogic settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Roles assigned to the Users. If a User who is designated personnel does not have the admin role, this is a finding.
4. Inspect the Roles assigned to the Users. If a User who is not designated personnel has the admin role, this is a finding.'
  desc 'fix', "Configure the DBMS's settings to allow designated personnel to select which auditable events are audited.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the Users icon on the left tree menu.
3. Inspect the Roles assigned to the Users. For designated personnel, assign the admin role and change user roles as necessary.
4. Inspect the Roles assigned to the Users. For non-designated personnel, remove the admin role and change user roles as necessary."
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22059r531250_chk'
  tag severity: 'medium'
  tag gid: 'V-220344'
  tag rid: 'SV-220344r622777_rule'
  tag stig_id: 'ML09-00-000600'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-22048r401484_fix'
  tag 'documentable'
  tag legacy: ['SV-110035', 'V-100931']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
