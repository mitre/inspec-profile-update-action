control 'SV-214044' do
  title 'If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden.'
  desc 'The SQL Server Browser simplifies the administration of SQL Server, particularly when multiple instances of SQL Server coexist on the same computer. It avoids the need to hard-assign port numbers to the instances and to set and maintain those port numbers in client systems. It enables administrators and authorized users to discover database management system instances, and the databases they support, over the network. SQL Server uses the SQL Server Browser service to enumerate instances of the Database Engine installed on the computer. This enables client applications to browse for a server, and helps clients distinguish between multiple instances of the Database Engine on the same computer.

This convenience also presents the possibility of unauthorized individuals gaining knowledge of the available SQL Server resources. Therefore, it is necessary to consider whether the SQL Server Browser is needed. Typically, if only a single instance is installed, using the default name (MSSQLSERVER) and port assignment (1433), the Browser is not adding any value. The more complex the installation, the more likely SQL Server Browser is to be helpful. 

This requirement is not intended to prohibit use of the Browser service in any circumstances.  It calls for administrators and management to consider whether the benefits of its use outweigh the potential negative consequences of it being used by an attacker to browse the current infrastructure and retrieve a list of running SQL Server instances.  In order to prevent this, the SQL instance(s) can be hidden.'
  desc 'check', %q(If the need for the SQL Server Browser service is documented and authorized, check to make sure the SQL Instances that do not require use of the SQL Browser Service are hidden with the following query: 

DECLARE @HiddenInstance INT 
EXEC master.dbo.Xp_instance_regread 
 N'HKEY_LOCAL_MACHINE', 
 N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib', 
 N'HideInstance', 
 @HiddenInstance output 

SELECT CASE 
        WHEN @HiddenInstance = 0 
             AND Serverproperty('IsClustered') = 0 THEN 'No' 
        ELSE 'Yes' 
      END AS [Hidden]

If the value of "Hidden" is "Yes", this is not a finding.

If the value of "Hidden" is "No" and the startup type of the "SQL Server Browser" service is not "Disabled", this is a finding.)
  desc 'fix', 'If SQL Server Browser is needed, document the justification and obtain the appropriate authorization. 

To hide the SQL instance, in SQL Server Configuration Manager, expand SQL Server Network Configuration, right-click Protocols for <server instance>, select "Properties", on the "Flags" tab, select "Yes" in the "HideInstance" box, then click "OK".  The change takes effect immediately for new connections.'
  impact 0.3
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15261r754689_chk'
  tag severity: 'low'
  tag gid: 'V-214044'
  tag rid: 'SV-214044r879887_rule'
  tag stig_id: 'SQL6-D0-018000'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-15259r313916_fix'
  tag 'documentable'
  tag legacy: ['SV-94059', 'V-79353']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
