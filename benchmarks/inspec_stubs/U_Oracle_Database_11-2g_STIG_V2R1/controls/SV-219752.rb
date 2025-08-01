control 'SV-219752' do
  title 'The DBMS must allow designated organizational personnel to select which auditable events are to be audited by the database.'
  desc 'The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

If the list of auditable events is not configurable, events that should be caught by auditing may be missed.  This may allow malicious activity to be overlooked.'
  desc 'check', 'Check DBMS settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.  If designated personnel are not able to configure auditable events, this is a finding.'
  desc 'fix', %q(Configure the DBMS's settings to allow designated personnel to select which auditable events are audited.

Note the following:
    In Oracle, any user can configure auditing for the objects in his or her own schema by using the AUDIT statement. To undo the audit configuration for an object, the user can use the NOAUDIT statement. No additional privileges are needed to perform this task.
    To audit objects in another schema, the user must have the AUDIT ANY system privilege.
    To audit system privileges, the user must have the AUDIT SYSTEM privilege.

For more information on the configuration of auditing, please refer to "Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/cd/E11882_01/server.112/e10575/tdpsg_auditing.htm
and "Verifying Security Access with Auditing" in the Oracle Database Security Guide:  http://docs.oracle.com/cd/E11882_01/network.112/e36292/auditing.htm#DBSEG006
and "27 DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/cd/E11882_01/appdev.112/e40758/d_audit_mgmt.htm)
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21477r307105_chk'
  tag severity: 'medium'
  tag gid: 'V-219752'
  tag rid: 'SV-219752r395709_rule'
  tag stig_id: 'O112-C2-006900'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-21476r307106_fix'
  tag 'documentable'
  tag legacy: ['SV-66683', 'V-52467']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
