control 'SV-224134' do
  title 'The EDB Postgres Advanced Server must be configured to provide audit record generation capability for DoD-defined auditable events within all EDB Postgres Advanced Server/database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following:

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', %q(Verify, using vendor and system documentation if necessary, that the DBMS is configured to use EDB's auditing features and configured to satisfy this requirement.

Execute the following SQL as the enterprisedb database user or another database superuser to check if EDB auditing is enabled:

 SHOW edb_audit;

If the result is not "csv" or "xml", this is a finding.

If organization-defined auditable events are not being audited, this is a finding.)
  desc 'fix', "Configure the DBMS's auditing to audit organization-defined auditable events.

Execute the following SQL as enterprisedb to ensure that EDB Auditing is enabled:

 ALTER SYSTEM SET edb_audit = csv;
 SELECT pg_reload_conf();

or

 ALTER SYSTEM SET edb_audit = xml;
 SELECT pg_reload_conf(); 

Configure EDB audit settings to audit organization-defined auditable events in accordance with the information documented in the EDB Postgres Advanced Server Guide."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25807r495422_chk'
  tag severity: 'medium'
  tag gid: 'V-224134'
  tag rid: 'SV-224134r508023_rule'
  tag stig_id: 'EP11-00-001000'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-25795r495423_fix'
  tag 'documentable'
  tag legacy: ['V-100295', 'SV-109399']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
