control 'SV-220305' do
  title 'The DBMS must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc "In order to ensure sufficient storage capacity for the audit logs, the DBMS must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates audit data be off-loaded to a centralized log management system, it remains necessary to provide space on the database server to serve as a buffer against outages and capacity limits of the off-loading mechanism.

The task of allocating audit record storage capacity is usually performed during initial installation of the DBMS and is closely associated with the DBA and system administrator roles. The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as: total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are off-loaded to the central log management system; and any limitations that exist on the DBMS's ability to reuse the space formerly occupied by off-loaded records."
  desc 'check', "Review the DBMS settings to determine whether audit logging is configured to produce logs consistent with the amount of space allocated for logging. If auditing will generate excessive logs so that they may outgrow the space reserved for logging, this is a finding.

If file-based auditing is in use, check that sufficient space is available to support the file(s). If not, this is a finding.

If standard, table-based auditing is used, the audit logs are written to a table called AUD$; and if a Virtual Private Database is deployed, a table is created called FGA_LOG$. First, check the current location of the audit trail tables.

CONN / AS SYSDBA

SELECT table_name, tablespace_name
FROM dba_tables
WHERE table_name IN ('AUD$', 'FGA_LOG$')
ORDER BY table_name;

TABLE_NAME TABLESPACE_NAME
------------------------------ ------------------------------
AUD$ SYSTEM
FGA_LOG$ SYSTEM

If the tablespace name is SYSTEM, the table needs to be relocated to its own tablespace. Ensure that adequate space is allocated to that tablespace.

If Unified Auditing is used:
Audit logs are written to tables in the AUDSYS schema. The default tablespace for AUDSYS is USERS. A separate tablespace should be created to contain audit data. Ensure that adequate space is allocated to that tablespace.
Investigate whether there have been any incidents where the DBMS ran out of audit log space since the last time the space was allocated or other corrective measures were taken. If there have been, this is a finding."
  desc 'fix', 'Allocate sufficient audit file/table space to support peak demand.

Ensure that audit tables are in their own tablespaces and that the tablespaces have enough room for the volume of log data that will be produced.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22020r533178_chk'
  tag severity: 'medium'
  tag gid: 'V-220305'
  tag rid: 'SV-220305r708413_rule'
  tag stig_id: 'O121-N2-008601'
  tag gtitle: 'SRG-APP-000109-DB-000049'
  tag fix_id: 'F-22012r533179_fix'
  tag 'documentable'
  tag legacy: ['SV-76343', 'V-61853']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
