control 'SV-81851' do
  title 'Where SQL Server Audit is in use at the database level, SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited at the database level.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.

This version of the requirement deals with SQL Server Audit-based audit trails."
  desc 'check', %q(If SQL Server Audit is not in use at the database level, this is not applicable (NA).

Obtain the list of approved audit maintainers from the system documentation.

Review the database roles and individual users that have the following permissions, both of which enable the ability to maintain audit definitions:
ALTER ANY DATABASE AUDIT
CONTROL ON DATABASE

The functions and views provided in the supplemental file Permissions.sql can assist in this review.  In the following, "STIG" stands for the schema where you have deployed these views and functions.  To see which logins and server roles have been granted these permissions:
    SELECT
        *
    FROM
        STIG.database_permissions P
    WHERE
        (P.[Permission] = 'ALTER ANY DATABASE AUDIT')
        OR
        (P.[Permission] = 'CONTROL' AND P.[Securable Type or Class] = 'DATABASE')
        ;

To see what users and database roles inherit these permissions from the database roles reported by the previous query, repeat the following for each one:
    SELECT * FROM STIG.members_of_database_role(<database role name>);

To see all the permissions in effect for a database principal (server role or login):
    SELECT * FROM STIG.server_effective_permissions(<principal name>); 

If designated personnel are not able to configure auditable events, this is a finding.

If unapproved personnel are able to configure auditable events, this is a finding.)
  desc 'fix', 'Create a database role specifically for audit maintainers, and give it permission to maintain audits, without granting it unnecessary permissions:
USE <database name>;
GO
CREATE ROLE DATABASE_AUDIT_MAINTAINERS;
GO
GRANT ALTER ANY DATABASE AUDIT TO DATABASE_AUDIT_MAINTAINERS;
GO
(The role name used here is an example; other names may be used.)

Use REVOKE and/or DENY and/or ALTER ROLE ... DROP MEMBER ... statements to remove the ALTER ANY DATABASE AUDIT permission from all users.

Then, for each authorized database user, run the statement:
ALTER ROLE DATABASE_AUDIT_MAINTAINERS ADD MEMBER <user name> ;
GO

Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements to remove CONTROL DATABASE permission from logins that do not need it.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67939r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67361'
  tag rid: 'SV-81851r2_rule'
  tag stig_id: 'SQL4-00-011320'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-73473r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
