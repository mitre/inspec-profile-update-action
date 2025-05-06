control 'SV-213964' do
  title 'If DBMS authentication using passwords is employed, SQL Server must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved. 
 
The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval. 
 
In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', %q(Check for use of SQL Server Authentication:

SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'SQL Server Authentication' END as [Authentication Mode]

If the returned value in the "[Authentication Mode]" column is "Windows Authentication", this is not a finding.

SQL Server should be configured to inherit password complexity and password lifetime rules from the operating system.

Review SQL Server to ensure logons are created with respect to the complexity settings and password lifetime rules by running the statement:

SELECT [name], is_expiration_checked, is_policy_checked
FROM sys.sql_logins

Review any accounts returned by the query other than the disabled SA account, ##MS_PolicyTsqlExecutionLogin##, and ##MS_PolicyEventProcessingLogin##.

If any account does not have both "is_expiration_checked" and "is_policy_checked" equal to “1”, this is a finding.

Review the Operating System settings relating to password complexity.

Determine whether the following rules are enforced. If any are not, this is a finding.

Check the server operating system for password complexity:

Navigate to Start >> All Programs >> Administrative Tools >> Local Security Policy, and to review the local policies on the machine, go to Account Policy >> Password Policy:.

Ensure the DISA Windows Password Policy is set on the SQL Server member server.)
  desc 'fix', 'Configure the SQL Server operating system and SQL Server logins for compliance. 

1. Ensure the password complexity requirements for the corresponding DISA Windows Server Security Technical Implementation Guide are met on the server where the SQL Server Instance is installed. 

2. Ensure SQL Server is configured to inherit password complexity rules from the operating system for SQL logins. Ensure check of policy and expiration are enforced when SQL logins are created. 

CREATE LOGIN <login_name> WITH PASSWORD= <enterStrongPasswordHere>, CHECK_EXPIRATION = ON, CHECK_POLICY = ON;'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15181r822458_chk'
  tag severity: 'high'
  tag gid: 'V-213964'
  tag rid: 'SV-213964r879601_rule'
  tag stig_id: 'SQL6-D0-007900'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-15179r313676_fix'
  tag 'documentable'
  tag legacy: ['SV-93897', 'V-79191']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
