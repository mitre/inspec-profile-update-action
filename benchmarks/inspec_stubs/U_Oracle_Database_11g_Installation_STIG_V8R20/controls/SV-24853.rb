control 'SV-24853' do
  title 'OS DBA group membership should be restricted to authorized accounts.'
  desc 'Oracle SYSDBA privileges include privileges to administer the database outside of database controls (when the database is shut down) in addition to all privileges controlled under database operation. Assignment of membership to the OS dba group to unauthorized persons can compromise all DBMS activities.'
  desc 'check', 'Review the membership for the Oracle DBA host system OS group.  

On UNIX systems:

  cat /etc/group | grep -i dba [where dba is the default group name from Oracle]

To display the group name if dba is not the default, use the command:

  cat $ORACLE_HOME/rdbms/lib/config.[cs] | grep SS_DBA_GRP

On Windows Systems:

Open Computer Management, expand System Tools, expand Local Users and Groups, select the Group folder.

Double-click on the ORA_DBA group to view group members.

Compare the list of members with the list of authorized DBA accounts documented in the System Security Plan with the IAO.

If any users are assigned to the group that are not authorized by the IAO and documented in the System Security Plan for the system, this is a Finding.'
  desc 'fix', 'Document user accounts that are authorized by the IAO to be assigned DBA privileges in the System Security Plan.

Remove any accounts assigned membership in the operating system DBA group that has not been authorized by the IAO.

Develop, document and implement procedures for periodic review of accounts assigned membership to the DBA group.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29411r1_chk'
  tag severity: 'low'
  tag gid: 'V-3845'
  tag rid: 'SV-24853r1_rule'
  tag stig_id: 'DO0145-ORACLE11'
  tag gtitle: 'Oracle SYSDBA OS group membership'
  tag fix_id: 'F-26438r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
