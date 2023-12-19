control 'SV-24546' do
  title 'The Oracle Management Agent should be uninstalled if not required and authorized or is installed on a database accessible from the Internet.'
  desc 'The Oracle Management Agent (Oracle Intelligent Agent in earlier versions) provides the mechanism for local and/or remote management of the local Oracle Database by Oracle Enterprise Manager or other SNMP management platforms. Because it provides access to operating system and database functions, it should be uninstalled if not in use.'
  desc 'check', "Determine if the Oracle Management Agent is installed:

From SQL*Plus:

  select account_status from dba_users
  where upper(username) = 'DBSNMP';

If no rows are returned, this is not a Finding.

If the DBSNMP account exists and the account_status is OPEN, then verify in the System Security Plan that operation and use of the Oracle Enterprise Manager Management Agent or another SNMP management program is documented and authorized.

If it is not documented in the System Security Plan as being required, this is a Finding.

If the DBSNMP account exists and the account_status is not OPEN, schedule the FIX action below then mark as not a Finding.

Despite any justification or authorization, if a Management Agent is installed on a DBMS server that is in a DMZ and Internet facing, this is a Finding."
  desc 'fix', 'Use the ORACLE_HOME/rdbms/admin/catnsnmp.sql script to remove all Oracle SNMP management agent objects in the database.

Delete the executable file ORACLE_HOME/bin/dbsnmp or dbsnmp.exe if it exists from any Oracle Home not authorized for SNMP management.

Uninstall any SNMP management agents installed on Oracle database servers installed in a DMZ that serve applications to Internet users.

Uninstall any SNMP management agents that have not been authorized and documented in the System Security Plan.

Document any authorized use of the SNMP management agent on database servers that do not support Internet applications in a DMZ in the System Security Plan.

NOTE: Removal of SNMP management objects will prevent the ability to generate database statistics within Oracle Enterprise Manager.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29457r1_chk'
  tag severity: 'low'
  tag gid: 'V-3866'
  tag rid: 'SV-24546r1_rule'
  tag stig_id: 'DO0430-ORACLE11'
  tag gtitle: 'Oracle management agent use'
  tag fix_id: 'F-26519r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
