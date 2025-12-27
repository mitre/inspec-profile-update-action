control 'SV-220343' do
  title 'MarkLogic Server must be configured to provide audit record generation capability for DoD-defined auditable events within all DBMS/database components.'
  desc "Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.

MarkLogic Server includes an auditing capability. Auditing can be enabled to capture security-relevant events to monitor suspicious database activity or to satisfy applicable auditing requirements. The generation of audit events can be configured by including or excluding MarkLogic Server roles, users, or documents based on URI. Some actions that can be audited are the following:
- Startup and shutdown of MarkLogic Server
- Adding or removing roles from a user
- Usage of amps
- Starting and stopping the auditing system

For the complete list of auditable events and their descriptions, see Auditing Events in the Administrator's Guide:
https://docs.marklogic.com/guide/admin/auditing"
  desc 'check', 'Check DBMS auditing to determine whether organization-defined auditable events are being audited by the system.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means there is no auditing and this is a finding. 
5. If audit enabled field is true, but the selected auditable events do not meet DoD minimum requirements, this is a finding.'
  desc 'fix', 'Configure MarkLogic to generate audit records for at least the DoD minimum or organization-defined set of events.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Configure the auditable events to meet DoD minimum requirements.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22058r401480_chk'
  tag severity: 'medium'
  tag gid: 'V-220343'
  tag rid: 'SV-220343r622777_rule'
  tag stig_id: 'ML09-00-000500'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-22047r401481_fix'
  tag 'documentable'
  tag legacy: ['SV-110033', 'V-100929']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
