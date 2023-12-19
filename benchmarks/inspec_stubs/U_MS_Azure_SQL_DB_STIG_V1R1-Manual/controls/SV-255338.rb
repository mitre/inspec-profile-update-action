control 'SV-255338' do
  title 'Azure SQL Database must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding Azure SQL Database management is presented on an interface available for users, information on Azure SQL Database settings may be inadvertently made available to the user.'
  desc 'check', 'To validate Azure role-based access controls (RBAC) for a specific resource, use the PowerShell script below:

$LogicalServerName = "myServer"
$ResourceScope = Get-AzResource -name $LogicalServerName | Where-Object {$_.ResourceType -eq "Microsoft.Sql/servers"} | Select-Object -ExpandProperty ResourceID

Get-AzRoleAssignment | Where-Object {$_.Scope -eq $ResourceScope}

If a user not assigned information system management responsibilities has membership in any of the following roles, this is a finding:

##SQL DB Contributor
##SQL Security Manager
##SQL Server Contributor
##User Access Administrator
##Owner
##Contributor
##Reader'
  desc 'fix', 'To remove an Azure RBAC role assignment, use Remove-AzRoleAssignment PowerShell command.

Example:
Remove-AzRoleAssignment `
      -SignInName "myAADIdenity" `
      -ResourceGroupName "myResourceGroup" `
      -ResourceName "myServerName" `
      -ResourceType "Microsoft.Sql/servers" `
      -RoleDefinitionName "myRole" `'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59011r871138_chk'
  tag severity: 'medium'
  tag gid: 'V-255338'
  tag rid: 'SV-255338r871140_rule'
  tag stig_id: 'ASQL-00-008900'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-58955r871139_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
