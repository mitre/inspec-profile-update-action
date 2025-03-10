control 'SV-24415' do
  title 'DBMS service identification should be unique and clearly identifies the service.'
  desc 'Local or network services that do not employ unique or clearly identifiable targets can lead to inadvertent or unauthorized connections.'
  desc 'check', 'Review the Oracle instance names on the DBMS host:

On UNIX platforms:
  Solaris:          cat /var/opt/oracle/oratab
  Other UNIX: cat /etc/oratab

The format of lines in the oratab file is:
  sid:oracle_home_directory:Y or N

The instance name is the sid.

On Windows platforms:
  Go to Start / Administrative Tools / Services 
  
View service names that begin with "OracleService".
 
The remainder of the service name is the instance name.
  Example:  OracleServicesalesDB -- where salesDB is the instance name

If instance names are listed and do not clearly identify the use of the instance or clearly differentiate individual instances, this is a Finding.

An example of instance naming that meets the requirement:  prdinv01 (Production Inventory Database #1), dvsales02 (Development Sales Database #2), orfindb1 (Oracle Financials Database #1).

Examples of instance naming that do not meet the requirement:  Instance1, MyInstance, orcl, 10gdb1

Interview the DBA to get an understanding of the naming scheme used to determine if the names are clear differentiations.'
  desc 'fix', 'Follow the instructions in Oracle Doc ID: 15390.1 to change the SID without re-creating the database.

Set the value so that it does not identify the Oracle version and clearly identifies its purpose.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29309r1_chk'
  tag severity: 'low'
  tag gid: 'V-15622'
  tag rid: 'SV-24415r1_rule'
  tag stig_id: 'DG0104-ORACLE11'
  tag gtitle: 'DBMS service identification'
  tag fix_id: 'F-26341r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
