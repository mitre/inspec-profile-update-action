control 'SV-238452' do
  title 'The DBMS itself, or the logging or alerting mechanism the application utilizes, must provide a warning when allocated audit record storage volume reaches an organization-defined percentage of maximum audit record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Audit processing failures include:  software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 

If audit log capacity were to be exceeded, then events subsequently occurring would not be recorded. Organizations shall define a maximum allowable percentage of storage capacity serving as an alarming threshold (e.g., application has exceeded 80% of log storage capacity allocated) at which time the application or the logging mechanism the application utilizes will provide a warning to the appropriate personnel.

A failure of database auditing will result in either the database continuing to function without auditing or in a complete halt to database operations. When audit processing fails, appropriate personnel must be alerted immediately to avoid further downtime or unaudited transactions.  This can be an alert provided by the database, a log repository, or the OS when a designated log directory is nearing capacity.'
  desc 'check', 'Review DBMS, OS, or third-party logging application settings to determine whether a warning will be provided when a specific percentage of log storage capacity is reached. If no warning will be provided, this is a finding.'
  desc 'fix', 'Modify DBMS, OS, or third-party logging application settings to alert appropriate personnel when a specific percentage of log storage capacity is reached.

For ease of management, it is recommended that the audit tables be kept in a dedicated tablespace.

If Oracle Enterprise Manager is in use, the capability to issue such an alert is built in and configurable via the console so an email can be sent to a designated administrator.

If Enterprise Manager is unavailable, the following script can be used to monitor storage space; this can be combined with additional code to email the appropriate administrator so they can take action.

sqlplus connect as sysdba

SQL> set pagesize 300  
SQL> set linesize 120  
SQL> column sumb format 9,999,999,999,999  
SQL> column extents format 999999  
SQL> column bytes format 9,999,999,999,999  
SQL> column largest format 9,999,999,999,999  
SQL> column Tot_Size format 9,999,999,999,999  
SQL> column Tot_Free format 9,999,999,999,999  
SQL> column Pct_Free format 9,999,999,999,999  
SQL> column Chunks_Free format 9,999,999,999,999   
SQL> column Max_Free format 9,999,999,999,999  
SQL> set echo off  
SQL> spool TSINFO.txt  
SQL> PROMPT  SPACE AVAILABLE IN TABLESPACES   
SQL> select a.tablespace_name,sum(a.tots) Tot_Size,   
SQL> sum(a.sumb) Tot_Free,  
SQL> sum(a.sumb)*100/sum(a.tots) Pct_Free,   
SQL> sum(a.largest) Max_Free,sum(a.chunks) Chunks_Free   
SQL> from   
SQL> (  
SQL> select tablespace_name,0 tots,sum(bytes) sumb,   
SQL> max(bytes) largest,count(*) chunks  
SQL> from dba_free_space a  
SQL> group by tablespace_name  
SQL> union  
SQL> select tablespace_name,sum(bytes) tots,0,0,0 from  
SQL> dba_data_files  
SQL> group by tablespace_name) a  
SQL> group by a.tablespace_name;  
 
 Sample Output
 
SPACE AVAILABLE IN TABLESPACES 
 
 TABLESPACE_NAME                     TOT_SIZE     TOT_FREE     PCT_FREE     MAX_FREE     CHUNKS_FREE
 ------------------------------      ------------ ------------ ------------ ------------ ------------ 
DES2                                 41,943,040   30,935,040       74       30,935,040        1 
DES2_I                               31,457,280   23,396,352       74       23,396,352        1 
RBS                                  60,817,408   57,085,952       94       52,426,752       16 
SYSTEM                               94,371,840    5,386,240        6        5,013,504        3 
TEMP                                    563,200      561,152      100          133,120        5 
TOOLS                               120,586,240   89,407,488       74       78,190,592       12 
USERS                                 1,048,576       26,624        3           26,624        1'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41663r667528_chk'
  tag severity: 'medium'
  tag gid: 'V-238452'
  tag rid: 'SV-238452r667530_rule'
  tag stig_id: 'O112-C2-008200'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-41622r667529_fix'
  tag 'documentable'
  tag legacy: ['V-52159', 'SV-66375']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
