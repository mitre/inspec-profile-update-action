control 'SV-224136' do
  title 'The EDB Postgres Advanced Server must generate audit records for DoD-defined auditable events.'
  desc 'The EDB Postgres Advanced Server must generate audit records for DoD-defined auditable events within all DBMS/database components.
  
Audit records should contain (at a minimum):
-Time stamps to establish when the events occurred
-Sufficient information to establish what type of events occurred
-Sufficient information to establish where the events occurred
-Sufficient information to establish the sources (origins) of the events
-Sufficient information to establish the outcome (success or failure) of the events
-Sufficient information to establish the identity of any user/subject or process associated with the event

Audit record content which may be necessary to investigate the events relating to an incident or identify those responsible for one. Audit policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality.

The list of minimum DoD-defined audit events includes:
-When privileges/permissions are retrieved, added, modified or deleted
-When unsuccessful attempts to retrieve, add, modify, delete privileges/permissions occur
-Enforcement of access restrictions associated with changes to the configuration of the database(s)
-When security objects are accessed, modified, or deleted
-When unsuccessful attempts to access, modify, or delete security objects occur
-When categories of information (e.g., classification levels/security levels) are accessed, created, modified, or deleted
-When unsuccessful attempts to access, create, modify, or delete categorized information occur
-All privileged activities or other system-level access
-When unsuccessful attempts to execute privileged activities or other system-level access occur
-When successful or unsuccessful access to objects occur

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.

'
  desc 'check', 'Execute the following SQL as enterprisedb:

SHOW edb_audit_statement;

If the result is not "all" or if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.'
  desc 'fix', "Execute the following SQL as enterprisedb:

ALTER SYSTEM SET edb_audit_statement = 'all';
SELECT pg_reload_conf();

or

Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25809r495428_chk'
  tag severity: 'medium'
  tag gid: 'V-224136'
  tag rid: 'SV-224136r557457_rule'
  tag stig_id: 'EP11-00-001200'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-25797r495429_fix'
  tag satisfies: ['SRG-APP-000095-DB-000039', 'SRG-APP-000091-DB-000325', 'SRG-APP-000096-DB-000040', 'SRG-APP-000097-DB-000041', 'SRG-APP-000098-DB-000042', 'SRG-APP-000099-DB-000043', 'SRG-APP-000100-DB-000201', 'SRG-APP-000381-DB-000361', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000494-DB-000344', 'SRG-APP-000494-DB-000345', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000498-DB-000346', 'SRG-APP-000498-DB-000347', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000502-DB-000348', 'SRG-APP-000502-DB-000349', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357']
  tag 'documentable'
  tag legacy: ['SV-109403', 'V-100299']
  tag cci: ['CCI-000172', 'CCI-000131', 'CCI-000134', 'CCI-001487', 'CCI-001814']
  tag nist: ['AU-12 c', 'AU-3 b', 'AU-3 e', 'AU-3 f', 'CM-5 (1)']
end
