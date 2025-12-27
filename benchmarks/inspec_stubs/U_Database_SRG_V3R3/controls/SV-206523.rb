control 'SV-206523' do
  title 'The DBMS must provide audit record generation capability for DoD-defined auditable events within all DBMS/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', 'Check DBMS auditing to determine whether organization-defined auditable events are being audited by the system.

If organization-defined auditable events are not being audited, this is a finding.'
  desc 'fix', 'Deploy a DBMS that supports the DoD minimum set of auditable events.

Configure the DBMS to generate audit records for at least the DoD minimum set of events.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6783r291237_chk'
  tag severity: 'medium'
  tag gid: 'V-206523'
  tag rid: 'SV-206523r617447_rule'
  tag stig_id: 'SRG-APP-000089-DB-000064'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-6783r291238_fix'
  tag 'documentable'
  tag legacy: ['SV-42699', 'V-32362']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
