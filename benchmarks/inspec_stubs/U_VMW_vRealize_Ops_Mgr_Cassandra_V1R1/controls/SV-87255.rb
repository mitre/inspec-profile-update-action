control 'SV-87255' do
  title 'The Cassandra database must provide audit record generation capability for DoD-defined auditable events within all database components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the DBMS (e.g., process, module). Certain specific application functionalities may be audited as well. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the DBMS will provide an audit record generation capability as the following: 

(i) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

(ii) Access actions, such as successful and unsuccessful logon attempts, privileged activities, or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system; and

(iii) All account creation, modification, disabling, and termination actions.

Organizations may define additional events requiring continuous or ad hoc auditing.'
  desc 'check', %q(Check the Cassandra Server auditing settings to determine whether organization-defined auditable events are being audited by the system.

At the command prompt, execute the following command:

# grep '<root' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If level is not set to "ALL", this is a finding.)
  desc 'fix', %q(Configure the Cassandra Server to generate audit records for at least the DoD minimum set of events.

At the command line execute the following command:

# sed -i 's/^\(\s*\\)<root level=".*">\(\s*\\)$/\1<root level="ALL">\2/' /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml)
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72623'
  tag rid: 'SV-87255r1_rule'
  tag stig_id: 'VROM-CS-000010'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-79025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
