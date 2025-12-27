control 'SV-89103' do
  title 'DB2 must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)'
  desc 'check', 'Determine whether the system documentation specifies limits on the number of concurrent DBMS sessions per account by type of user. If it does not, assume a limit of 10 for database administrators and 2 for all other users.

The DB2 CONNECT_PROC configuration parameter allows the input of a two-part connect procedure name that will implicitly be executed every time an application connects to the database.
 
Find the value of CONNECT_PROC by running the following command:

     $db2 get db cfg

If the value of CONNECT_PROC is null (i.e., not set), this is a finding. 

If the value of CONNECT_PROC is set, run the following command to review the DDL for the connect procedure: 
DB2> SELECT text FROM SYSCAT.ROUTINES WHERE ROUTINENAME=<MY_CONNECT>

If the connect procedure does not restrict the user sessions as per organization guidelines, this is a finding.'
  desc 'fix', "Create the stored procedure per organization guidelines to restrict the number of concurrent sessions using the CREATE or REPLACE procedure:
DB2> CREATE or REPLACE   PROCEDURE <DBINST1.MY_CONNECT> (Example below.)

Update the database CONNECT_PROC parameter to set to the procedure created in previous step:

     $db2 update db cfg using CONNECT_PROC db2inst1.my_connect

Grant execute to the public to connect the procedure.
DB2> GRANT EXECUTE ON procedure <schema>.MY_CONNECT_MAIN TO PUBLIC

Note:  This is an example. Modify and test to comply with organization policy.

CREATE OR REPLACE PROCEDURE db2inst1.my_connect_main()
BEGIN
   DECLARE vcount integer;
   DECLARE vcount_admin integer;
 SELECT COUNT(*) INTO vcount FROM table(mon_get_connection(NULL, NULL, 0)) WHERE session_auth_id = session_user and application_handle != mon_get_application_handle();
 SELECT COUNT(*) INTO vcount_admin FROM table (sysproc.auth_list_authorities_for_authid(session_user,'U')) as t WHERE authority in ('SYSMON','SYSADM','DBADM','SECADM','SYSCTRL','SYSMAINT')and (d_user='Y' OR d_group='Y' OR d_public='Y' OR role_user='Y' or role_group='Y' or role_public='Y' or d_role='Y');
IF (vcount_admin > 0 AND vcount > 5)
THEN
      SIGNAL SQLSTATE '42502' SET MESSAGE_TEXT='Connection refused. More than 5 connections not allowed for admin!';
ELSEIF (vcount > 3 AND vcount_admin = 0)
THEN
      SIGNAL SQLSTATE '42502' SET MESSAGE_TEXT='Connection refused. More than 3 connections not allowed!';
END IF;
END
@ 

Note: @ sign in above statement is statement terminator, using db2 –t option, statement terminator can be changed 

DB2> GRANT EXECUTE ON PROCEDURE  db2inst1.my_connect_main TO PUBLIC

     $db2 UPDATE DB CFG USING CONNECT_PROC db2inst1. my_connect_main"
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74355r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74429'
  tag rid: 'SV-89103r1_rule'
  tag stig_id: 'DB2X-00-000200'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-81029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
