control 'SV-53411' do
  title 'SQL Server must be configured to use Windows Integrated Security.'
  desc 'SQL Server Authentication does not provide for many of the authentication requirements of the DoD. In some cases workarounds are present, but the authentication is not as robust and does not provide needed functionality. Without that functionality, SQL Server is vulnerable to authentication attacks. Consideration must be given to the placement of SQL server inside a forest to ensure evaluation of risk within the environment is considered. Risk includes introduction of risk to SQL Server from other applications or workstations as well as risk from introduction of SQL server itself into an established environment.

There may be situations where SQL Server Authentication must remain enabled, because of constraints imposed by a third-party application.  In such a case, document the constraint in the system security plan, and obtain signed approval.'
  desc 'check', %q(To determine the Server Authentication Mode, execute the following:

EXEC XP_LOGINCONFIG 'login mode'

If the config_value does not equal "Windows NT Authentication", this is a finding.)
  desc 'fix', 'From SQL Server Management Studio, right-click the server, and then click Properties.

Select the Security page. Under Server authentication, select Windows Authentication Mode, and then click OK.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47653r3_chk'
  tag severity: 'medium'
  tag gid: 'V-41036'
  tag rid: 'SV-53411r5_rule'
  tag stig_id: 'SQL2-00-023600'
  tag gtitle: 'SRG-APP-999999-DB-000209'
  tag fix_id: 'F-46335r4_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
