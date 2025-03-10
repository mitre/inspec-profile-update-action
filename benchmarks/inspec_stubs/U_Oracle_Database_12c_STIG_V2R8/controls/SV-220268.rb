control 'SV-220268' do
  title 'The DBMS must allow designated organizational personnel to select which auditable events are to be audited by the database.'
  desc 'The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

If the list of auditable events is not configurable, events that should be caught by auditing may be missed.  This may allow malicious activity to be overlooked.'
  desc 'check', 'Check DBMS settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.  If designated personnel are not able to configure auditable events, this is a finding.'
  desc 'fix', %q(Configure the DBMS's settings to allow designated personnel to select which auditable events are audited.

Note the following:
In Oracle, any user can configure auditing for the objects in his or her own schema by using the AUDIT statement. To undo the audit configuration for an object, the user can use the NOAUDIT statement. No additional privileges are needed to perform this task.

To audit objects in another schema, the user must have the AUDIT ANY system privilege.
To audit system privileges, the user must have the AUDIT SYSTEM privilege.

For more information on the configuration of auditing, refer to the following documents:
"Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/database/121/TDPSG/tdpsg_auditing.htm#TDPSG50000
"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide:
http://docs.oracle.com/database/121/DBSEG/part_6.htm#CCHEHCGI
"DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/database/121/ARPLS/d_audit_mgmt.htm#ARPLS241)
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21983r391935_chk'
  tag severity: 'medium'
  tag gid: 'V-220268'
  tag rid: 'SV-220268r879560_rule'
  tag stig_id: 'O121-C2-006900'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-21975r391936_fix'
  tag 'documentable'
  tag legacy: ['SV-76113', 'V-61623']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
