control 'SV-255346' do
  title 'Azure SQL Database must only use approved firewall settings deemed by the organization to be secure, including denying public network access.'
  desc 'Use of nonsecure firewall settings, such as allowing public access, exposes the system to avoidable threats.'
  desc 'check', 'Azure SQL Database must only use approved firewall settings, including denying public network access. This value is allowed by default in Azure SQL Database and should be disabled if not otherwise documented and approved.
 
Obtain a list of approved firewall settings from the database documentation. 
 
Verify that the public network access option is set to disabled.
 
If the value is enabled and not in use and specifically approved in the database documentation, this is a finding.

1. From the Azure Portal Dashboard, click "Set Server Firewall".
2. Review the Allow Azure services and resources to access this server option.'
  desc 'fix', 'Assign the approved policy to Azure SQL Database.
1. From the Azure Portal Dashboard, click on the database.
2. Click "Set Server Firewall".
3. Review the public network access option.
4. Check the box to "Disable" public network access.
5. Click "Save".

For more information about connection policies:
https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59019r871162_chk'
  tag severity: 'medium'
  tag gid: 'V-255346'
  tag rid: 'SV-255346r871164_rule'
  tag stig_id: 'ASQL-00-011900'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-58963r871163_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
