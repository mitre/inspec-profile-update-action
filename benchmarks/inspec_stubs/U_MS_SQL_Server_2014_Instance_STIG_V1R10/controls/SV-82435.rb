control 'SV-82435' do
  title 'If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password lifetime.'
  desc 'Windows domain/enterprise authentication and identification must be used (SQL4-00-030300).  Native SQL Server authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates.  Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password lifetime must be implemented.  

The requirements for password lifetime are:
a. Password lifetime limits for interactive accounts:  Minimum 24 hours, Maximum 60 days
b. Password lifetime limits for non-interactive accounts:  Minimum 24 hours, Maximum 365 days
c. Number of password changes before an old one may be reused:  Minimum of 5.

To enforce this in SQL Server, configure each DBMS-managed login to inherit the rules from Windows.'
  desc 'check', "Run the statement:
SELECT
    name
FROM 
    sys.sql_logins 
WHERE
    type_desc = 'SQL_LOGIN'
    AND is_disabled = 0
    AND is_expiration_checked = 0; 

If no account names are listed, this is not a finding.

For each account name listed, determine whether it is documented as requiring exemption from the standard password lifetime rules, if it is not, this is a finding."
  desc 'fix', 'For each SQL Server Login identified in the Check as out of compliance:
In SQL Server Management Studio Object Explorer, navigate to <SQL Server instance name> >> Security >> Logins >> <login name>.  Right-click, select Properties.  Select the check box Enforce Password Expiration.  Click OK.

Alternatively, for each identified Login, run the statement:
ALTER LOGIN <login name>  CHECK_EXPIRATION = ON;'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68515r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67945'
  tag rid: 'SV-82435r2_rule'
  tag stig_id: 'SQL4-00-038910'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-74061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198', 'CCI-000199', 'CCI-000200']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-5 (1) (e)']
end
