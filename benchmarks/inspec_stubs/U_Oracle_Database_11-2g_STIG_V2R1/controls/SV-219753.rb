control 'SV-219753' do
  title 'The DBMS must generate audit records for the DoD-selected list of auditable events, to the extent such information is available.'
  desc 'Audit records can be generated from various components within the information system, such as network interfaces, hard disks, modems, etc. From an application perspective, certain specific application functionalities may be audited, as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

Organizations may define the organizational personnel accountable for determining which application components shall provide auditable events.

Auditing provides accountability for changes made to the DBMS configuration or its objects and data. It provides a means to discover suspicious activity and unauthorized changes. Without auditing, a compromise may go undetected and without a means to determine accountability.

The Department of Defense has established the following as the minimum set of auditable events.  Most can be audited via Oracle settings; some may require OS settings.

- Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g. classification levels). 

- Successful and unsuccessful logon attempts, privileged activities or other system level access

- Starting and ending time for user access to the system, concurrent logons from different workstations.

- Successful and unsuccessful accesses to objects.

- All program initiations.

- All direct access to the information system.

- All account creations, modifications, disabling, and terminations. 

- All kernel module loads, unloads, and restarts.'
  desc 'check', 'Check DBMS and OS settings to determine if auditing is being performed on the events on the DoD-selected list of auditable events.  If auditing is not being performed for any of the events on the DoD-selected list of auditable events, this is a finding.'
  desc 'fix', %q(Configure the DBMS's auditing settings to include auditing of events on the DoD-selected list of auditable events.

For more information on the configuration of auditing in the DBMS, please refer to "Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/cd/E11882_01/server.112/e10575/tdpsg_auditing.htm
and "Verifying Security Access with Auditing" in the Oracle Database Security Guide:  http://docs.oracle.com/cd/E11882_01/network.112/e36292/auditing.htm#DBSEG006
and "27 DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/cd/E11882_01/appdev.112/e40758/d_audit_mgmt.htm)
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21478r307108_chk'
  tag severity: 'medium'
  tag gid: 'V-219753'
  tag rid: 'SV-219753r395712_rule'
  tag stig_id: 'O112-C2-007000'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-21477r307109_fix'
  tag 'documentable'
  tag legacy: ['SV-66685', 'V-52469']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
