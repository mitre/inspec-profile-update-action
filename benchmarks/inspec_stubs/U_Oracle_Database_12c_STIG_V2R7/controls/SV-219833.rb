control 'SV-219833' do
  title 'The Oracle password file ownership and permissions should be limited and the REMOTE_LOGIN_PASSWORDFILE parameter must be set to EXCLUSIVE or NONE.'
  desc 'It is critically important to the security of your system that you protect your password file and the environment variables that identify the location of the password file. Any user with access to these could potentially compromise the security of the connection. 
The REMOTE_LOGIN_PASSWORDFILE setting of "NONE" disallows remote administration of the database. The REMOTE_LOGIN_PASSWORDFILE setting of "EXCLUSIVE" allows for auditing of individual DBA logons to the SYS account. If not set to "EXCLUSIVE", remote connections to the database as "internal" or "as SYSDBA" are not logged to an individual account.'
  desc 'check', "From SQL*Plus:

select value from v$parameter where upper(name) = 'REMOTE_LOGIN_PASSWORDFILE';

If the value returned does not equal 'EXCLUSIVE' or 'NONE', this is a finding.

On UNIX Systems:

ls -ld $ORACLE_HOME/dbs/orapw${ORACLE_SID}

Substitute ${ORACLE_SID} with the name of the ORACLE_SID for the database.

If permissions are granted for world access, this is a finding.

On Windows Systems (From Windows Explorer):

Browse to the %ORACLE_HOME\\database\\directory.

Select and right-click on the PWD%ORACLE_SID%.ora file, select Properties, select the Security tab.
Substitute %ORACLE_SID% with the name of the ORACLE_SID for the database.

If permissions are granted to everyone, this is a finding.
If any account other than the DBMS software installation account is listed, this is a finding."
  desc 'fix', "Disable use of the REMOTE_LOGIN_PASSWORDFILE where remote administration is not authorized by specifying a value of NONE.

If authorized, restrict use of a password file to exclusive use by each database by specifying a value of EXCLUSIVE.

From SQL*Plus:

alter system set REMOTE_LOGIN_PASSWORDFILE = 'EXCLUSIVE' scope = spfile;

OR

alter system set REMOTE_LOGIN_PASSWORDFILE = 'NONE' scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.

Restrict ownership and permissions on the Oracle password file to exclude world (Unix) or everyone (Windows).

More information regarding the ORAPWD file and the REMOTE_LOGIN_PASSWORDFILE parameter, can be found here:
https://docs.oracle.com/database/121/ADMIN/dba.htm#ADMIN12478"
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21544r533038_chk'
  tag severity: 'medium'
  tag gid: 'V-219833'
  tag rid: 'SV-219833r879887_rule'
  tag stig_id: 'O121-BP-022200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21543r533039_fix'
  tag 'documentable'
  tag legacy: ['SV-75921', 'V-61431']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
