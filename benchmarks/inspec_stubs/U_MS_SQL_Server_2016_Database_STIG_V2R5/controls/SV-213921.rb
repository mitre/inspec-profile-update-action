control 'SV-213921' do
  title 'SQL Server must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', "Review system documentation to determine requirements for object ownership and authorization delegation.

Use the following query to discover database object ownership:

Schemas not owned by the schema or dbo:

SELECT name AS schema_name, USER_NAME(principal_id) AS schema_owner
FROM sys.schemas
WHERE schema_id != principal_id
 AND principal_id != 1

Objects owned by an individual principal:

SELECT object_id, name AS securable, 
  USER_NAME(principal_id) AS object_owner,
  type_desc
FROM sys.objects
WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
ORDER BY type_desc, securable, object_owner

Use the following query to discover database users who have been delegated the right to assign additional permissions:

SELECT U.type_desc, U.name AS grantee,
 DP.class_desc AS securable_type,
   CASE DP.class
    WHEN 0 THEN DB_NAME()
    WHEN 1 THEN OBJECT_NAME(DP.major_id) 
    WHEN 3 THEN SCHEMA_NAME(DP.major_id)
   ELSE CAST(DP.major_id AS nvarchar)
   END AS securable,
       permission_name, state_desc
FROM sys.database_permissions DP
JOIN sys.database_principals U ON DP.grantee_principal_id = U.principal_id
WHERE DP.state = 'W'
ORDER BY grantee, securable_type, securable

If any of these rights are not documented and authorized, this is a finding."
  desc 'fix', 'To correct object ownership:

ALTER AUTHORIZATION ON <Securable> TO <Principal>

To revoke any unauthorized permissions:

REVOKE [Permission] ON <Securable> TO <Principal>'
  impact 0.3
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15139r313195_chk'
  tag severity: 'low'
  tag gid: 'V-213921'
  tag rid: 'SV-213921r855956_rule'
  tag stig_id: 'SQL6-D0-002800'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-15137r313196_fix'
  tag 'documentable'
  tag legacy: ['SV-93811', 'V-79105']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
