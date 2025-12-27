control 'SV-213937' do
  title 'SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events. 
 
Suppression of auditing could permit an adversary to evade detection. 
 
Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', "Obtain the list of approved audit maintainers from the system documentation. 
 
Review the server roles and individual logins that have the following role memberships, all of which enable the ability to create and maintain audit definitions. 
 
sysadmin 
dbcreator 
 
Review the server roles and individual logins that have the following permissions, all of which enable the ability to create and maintain audit definitions. 
 
ALTER ANY SERVER AUDIT  
CONTROL SERVER  
ALTER ANY DATABASE  
CREATE ANY DATABASE 
 
Use the following query to determine the roles and logins that have the listed permissions: 
 
SELECT-- DISTINCT 
    CASE 
        WHEN SP.class_desc IS NOT NULL THEN  
            CASE 
                WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER' 
                WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)' 
                ELSE SP.class_desc 
            END 
        WHEN E.name IS NOT NULL THEN 'ENDPOINT' 
        WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER' 
        WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)' 
        WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL' 
        ELSE '???'  
    END                    AS [Securable Class], 
    CASE 
        WHEN E.name IS NOT NULL THEN E.name 
        WHEN S.name IS NOT NULL THEN S.name  
        WHEN P.name IS NOT NULL THEN P.name 
        ELSE '???'  
    END                    AS [Securable], 
    P1.name                AS [Grantee], 
    P1.type_desc           AS [Grantee Type], 
    sp.permission_name     AS [Permission], 
    sp.state_desc          AS [State], 
    P2.name                AS [Grantor], 
    P2.type_desc           AS [Grantor Type], 
R.name    AS [Role Name] 
FROM 
    sys.server_permissions SP 
    INNER JOIN sys.server_principals P1 
        ON P1.principal_id = SP.grantee_principal_id 
    INNER JOIN sys.server_principals P2 
        ON P2.principal_id = SP.grantor_principal_id 
 
    FULL OUTER JOIN sys.servers S 
        ON  SP.class_desc = 'SERVER' 
        AND S.server_id = SP.major_id 
 
    FULL OUTER JOIN sys.endpoints E 
        ON  SP.class_desc = 'ENDPOINT' 
        AND E.endpoint_id = SP.major_id 
 
    FULL OUTER JOIN sys.server_principals P 
        ON  SP.class_desc = 'SERVER_PRINCIPAL'         
        AND P.principal_id = SP.major_id 
 
FULL OUTER JOIN sys.server_role_members SRM 
ON P.principal_id = SRM.member_principal_id 
 
LEFT OUTER JOIN sys.server_principals R 
ON SRM.role_principal_id = R.principal_id 
WHERE sp.permission_name IN ('ALTER ANY SERVER AUDIT','CONTROL SERVER','ALTER ANY DATABASE','CREATE ANY DATABASE') 
OR R.name IN ('sysadmin','dbcreator') 
 
If any of the logins, roles, or role memberships returned have permissions that are not documented, or the documented audit maintainers do not have permissions, this is a finding."
  desc 'fix', 'Create a server role specifically for audit maintainers and give it permission to maintain audits without granting it unnecessary permissions (the role name used here is an example; other names may be used):   
 
CREATE SERVER ROLE SERVER_AUDIT_MAINTAINERS; 
GO 
 
GRANT ALTER ANY SERVER AUDIT TO SERVER_AUDIT_MAINTAINERS; 
GO     
 
Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements to remove the ALTER ANY SERVER AUDIT permission from all logins.  Then, for each authorized login, run the statement:   
 
ALTER SERVER ROLE SERVER_AUDIT_MAINTAINERS ADD MEMBER; 
GO 
 
Use REVOKE and/or DENY and/or ALTER SERVER ROLE ... DROP MEMBER ... statements to remove CONTROL SERVER, ALTER ANY DATABASE and CREATE ANY DATABASE permissions from logins that do not need them.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15154r313594_chk'
  tag severity: 'medium'
  tag gid: 'V-213937'
  tag rid: 'SV-213937r879560_rule'
  tag stig_id: 'SQL6-D0-004400'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-15152r313595_fix'
  tag 'documentable'
  tag legacy: ['SV-93841', 'V-79135']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
