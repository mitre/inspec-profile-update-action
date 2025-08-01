control 'SV-24391' do
  title 'Production databases should be protected from unauthorized access by developers on shared production/development host systems.'
  desc 'Developers granted elevated database, operating system privileges on systems that support both development, and production databases can affect the operation and/or security of the production database system. Operating system and database privileges assigned to developers on shared development and production systems should be restricted.'
  desc 'check', "Review the list of instances and databases installed on the host system with the DBA.

Ask which databases are production databases and which are for development.  

For UNIX systems, use the ps -ef|grep pmon command to see the list of databases; For Windows systems, review the list of services beginning with the name OracleService to see the list of databases.

Ask which databases are production databases and which are for development.

If only development or only production databases exist on this host, this check is Not a Finding. 

Otherwise, ask the DBA to confirm that policy and procedures are in place for the IAO to review database and operating system privileges on the system to ensure developer accounts do not have access to production DBMS systems.

If none are in place, this is a Finding. 
 
Ask the DBA/SA if developer host accounts have been granted privileges to production database directories, files or resources.

If they have been, this is a Finding. 

From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):
  select grantee||': '||privilege from dba_sys_privs
  where (privilege like 'CREATE%' or privilege like 'ALTER%'
   or privilege like 'DROP%')
  and privilege<>'CREATE SESSION'
  and grantee not in
  ('ANONYMOUS','AURORA$JIS$UTILITY$',
   'AURORA$ORB$UNAUTHENTICATED','CTXSYS','DBSNMP','DIP',
   'DVF','DVSYS','EXFSYS','LBACSYS','MDDATA','MDSYS','MGMT_VIEW',
   'ODM','ODM_MTR','OLAPSYS','ORDPLUGINS','ORDSYS',
   'OSE$HTTP$ADMIN','OUTLN','PERFSTAT','PUBLIC','REPADMIN',
   'RMAN','SI_INFORMTN_SCHEMA','SYS','SYSMAN','SYSTEM',
   'TRACESVR','TSMSYSWK_TEST','WKPROXY','WKSYS','WKUSER',
   'WMSYS','XDB')
  order by grantee;

If any accounts are listed that are not on the list of IAO approved production DBAs, this is a Finding.

NOTE: Though shared production/non-production DBMS installations was allowed under previous database STIG guidance, doing so may place it in violation of OS, Application, Network or Enclave STIG guidance. Ensure that any shared production/non-production DBMS installations meets STIG guidance requirements at all levels or mitigate any conflicts in STIG guidance with your DAA."
  desc 'fix', 'Develop, document and implement procedures to review and maintain privileges granted to developers on shared production and development host systems and databases.

Recommend establishing a dedicated DBMS host for production DBMS installations (See Checks DG0109 and DG0110).

A dedicated host system in this case refers to an instance of the operating system at a minimum.

The operating system may reside on a virtual host machine where supported by the DBMS vendor.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-28658r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3820'
  tag rid: 'SV-24391r2_rule'
  tag stig_id: 'DG0077-ORACLE11'
  tag gtitle: 'Production data protection on a shared system'
  tag fix_id: 'F-25685r1_fix'
  tag responsibility: 'Database Administrator'
end
