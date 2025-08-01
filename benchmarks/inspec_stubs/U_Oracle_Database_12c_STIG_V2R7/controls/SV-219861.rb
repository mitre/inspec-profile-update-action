control 'SV-219861' do
  title 'The DBMS data files, transaction logs and audit files must be stored in dedicated directories or disk partitions separate from software or other application files.'
  desc "Protection of DBMS data, transaction and audit data files stored by the host operating system is dependent on OS controls. When different applications share the same database, resource contention and security controls are required to isolate and protect an application's data from other applications. In addition, it is an Oracle best practice to separate data, transaction logs, and audit logs into separate physical directories according to Oracle’s OFA (Optimal Flexible Architecture). And finally, DBMS software libraries and configuration files also require differing access control lists."
  desc 'check', 'Review the disk/directory specification where database data, transaction log and audit files are stored.

If DBMS data, transaction log or audit data files are stored in the same directory, this is a finding.

If multiple applications are accessing the database and the database data files are stored in the same directory, this is a finding.

If multiple applications are accessing the database and database data is separated into separate physical directories according to application, this check is not a finding.'
  desc 'fix', 'Specify dedicated host system disk directories to store database data, transaction and audit files.
Example directory structure:
/*/app/oracle/oradata/db_name
/*/app/oracle/admin/db_name/arch/*
/*/app/oracle/oradata/db_name/audit
/*/app/oracle/fast_recovery_area/db_name/

See Oracle Optimal Flexible Architecture:
https://docs.oracle.com/database/121/LADBI/appendix_ofa.htm#LADBI7921

When multiple applications are accessing a single database, configure DBMS default file storage according to application to use dedicated disk directories. 

/*/app/oracle/oradata/db_name/app_name

See Oracle Optimal Flexible Architecture:
https://docs.oracle.com/database/121/LADBI/appendix_ofa.htm#LADBI7921'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21572r533106_chk'
  tag severity: 'medium'
  tag gid: 'V-219861'
  tag rid: 'SV-219861r879887_rule'
  tag stig_id: 'O121-BP-025100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21571r533107_fix'
  tag 'documentable'
  tag legacy: ['SV-76453', 'V-61963']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
