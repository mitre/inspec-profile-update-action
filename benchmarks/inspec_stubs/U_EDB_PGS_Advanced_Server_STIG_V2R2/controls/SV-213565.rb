control 'SV-213565' do
  title 'The EDB Postgres Advanced Server must provide audit record generation capability for DoD-defined auditable events within all EDB Postgres Advanced Server/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW edb_audit;
 
If the result is not "csv" or "xml", this is a finding.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

ALTER SYSTEM SET edb_audit = csv;
SELECT pg_reload_conf();

or

ALTER SYSTEM SET edb_audit = xml;
SELECT pg_reload_conf();'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14787r290007_chk'
  tag severity: 'medium'
  tag gid: 'V-213565'
  tag rid: 'SV-213565r508024_rule'
  tag stig_id: 'PPS9-00-001000'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-14785r290008_fix'
  tag 'documentable'
  tag legacy: ['SV-83487', 'V-68883']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
