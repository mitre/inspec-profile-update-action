control 'SV-252134' do
  title 'MongoDB must provide audit record generation for DoD-defined auditable events within all DBMS/database components.'
  desc 'MongoDB must provide audit record generation capability for DoD-defined auditable events within all DBMS/database components.

'
  desc 'check', %q(Check the MongoDB configuration file (default location: /etc/mongod.conf) for appropriate audit configuration keys.

Examples shown below:

auditLog:
   destination: file
   format: BSON
   path: /var/log/mongodb/audit/auditLog.bson

-OR-

auditLog:
destination: syslog

If an auditLog key is not present, this is a finding.

If the MongoDB configuration file does not contain a setParameter option with auditAuthorizationSuccess: true, this is a finding.

Example:
setParameter:
  auditAuthorizationSuccess: true

If the auditLog key is present and contains a filter subkey without an associated filter, this is a finding.

The site auditing policy must be reviewed to determine if the filter being applied meets the site auditing requirements. If not, then the filter being applied will need to be modified to comply.

Example filter shown below only audits createCollection and dropCollection:

auditLog:
   destination: file
   format: BSON
   path: /var/log/mongodb/audit/auditLog.bson
   filter: '{ atype: { $in: [ "createCollection", "dropCollection" ] } }')
  desc 'fix', 'If the auditLog setting was not present in the %MongoDB configuration file% (default location: /etc/mongod.conf) edit this file and add a configured auditLog setting:

auditLog:
   destination: file
   format: BSON
   path: /var/log/mongodb/audit/auditLog.bson

Note: The "/var/log/mongodb/audit" directory will need to be created/present or the database will not start.

Alternately, the audit logs can be written to syslog with the following setting:
auditLog:
destination: syslog

This setting will record the following operations: schema (DDL),  replica set and sharded cluster and authentication and authorization.

To capture all operations in the audit, enable the audit system to log authorization successes by adding the following line to  the /etc/mongod.conf file:

setParameter: 
    auditAuthorizationSuccess: true

Stop/start (restart) the mongod or mongos instance using this configuration.

If the auditLog setting was present and contained a filter parameter, ensure the filter expression does not prevent the auditing of events that should be audited or remove the filter parameter to enable auditing all events.

Documentation on configuring filters can be found here:

https://docs.mongodb.com/v4.4/tutorial/configure-audit-filters/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55590r855499_chk'
  tag severity: 'medium'
  tag gid: 'V-252134'
  tag rid: 'SV-252134r855500_rule'
  tag stig_id: 'MD4X-00-000100'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-55540r813783_fix'
  tag satisfies: ['SRG-APP-000089-DB-000064', 'SRG-APP-000080-DB-000063', 'SRG-APP-000090-DB-000065', 'SRG-APP-000091-DB-000066', 'SRG-APP-000091-DB-000325', 'SRG-APP-000092-DB-000208', 'SRG-APP-000095-DB-000039', 'SRG-APP-000096-DB-000040', 'SRG-APP-000097-DB-000041', 'SRG-APP-000098-DB-000042', 'SRG-APP-000099-DB-000043', 'SRG-APP-000100-DB-000201', 'SRG-APP-000101-DB-000044', 'SRG-APP-000109-DB-000049', 'SRG-APP-000356-DB-000315', 'SRG-APP-000360-DB-000320', 'SRG-APP-000381-DB-000361', 'SRG-APP-000492-DB-000332', 'SRG-APP-000492-DB-000333', 'SRG-APP-000494-DB-000344', 'SRG-APP-000494-DB-000345', 'SRG-APP-000495-DB-000326', 'SRG-APP-000495-DB-000327', 'SRG-APP-000495-DB-000328', 'SRG-APP-000495-DB-000329', 'SRG-APP-000496-DB-000334', 'SRG-APP-000496-DB-000335', 'SRG-APP-000498-DB-000346', 'SRG-APP-000498-DB-000347', 'SRG-APP-000499-DB-000330', 'SRG-APP-000499-DB-000331', 'SRG-APP-000501-DB-000336', 'SRG-APP-000501-DB-000337', 'SRG-APP-000502-DB-000348', 'SRG-APP-000502-DB-000349', 'SRG-APP-000503-DB-000350', 'SRG-APP-000503-DB-000351', 'SRG-APP-000504-DB-000354', 'SRG-APP-000504-DB-000355', 'SRG-APP-000505-DB-000352', 'SRG-APP-000506-DB-000353', 'SRG-APP-000507-DB-000356', 'SRG-APP-000507-DB-000357', 'SRG-APP-000508-DB-000358', 'SRG-APP-000515-DB-000318']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000140', 'CCI-000166', 'CCI-000171', 'CCI-000172', 'CCI-001464', 'CCI-001487', 'CCI-001814', 'CCI-001844', 'CCI-001851', 'CCI-001858']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-5 b', 'AU-10', 'AU-12 b', 'AU-12 c', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)', 'AU-3 (2)', 'AU-4 (1)', 'AU-5 (2)']
end
