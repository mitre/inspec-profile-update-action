control 'SV-87037' do
  title 'If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password complexity.'
  desc '<0> [object Object]'
  desc 'check', "Run the statement:
SELECT
    name
FROM 
    sys.sql_logins 
WHERE
    type_desc = 'SQL_LOGIN'
    AND is_disabled = 0
    AND is_policy_checked = 0 ; 

If no account names are listed, this is not a finding.

For each account name listed, determine whether it is documented as requiring exemption from the standard password complexity rules.  If it is not, this is a finding."
  desc 'fix', 'For each SQL Server Login identified in the Check as out of compliance:
In SQL Server Management Studio Object Explorer, navigate to <SQL Server instance name> >> Security >> Logins >> <login name>.  Right-click, select Properties.  Select the check box Enforce Password Policy.  Click OK.

Alternatively, for each identified Login, run the statement:
ALTER LOGIN <login name> CHECK_POLICY = ON;'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-72667r2_chk'
  tag severity: 'medium'
  tag gid: 'V-72413'
  tag rid: 'SV-87037r1_rule'
  tag stig_id: 'SQL2-00-038900'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-78881r1_fix'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000205', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
