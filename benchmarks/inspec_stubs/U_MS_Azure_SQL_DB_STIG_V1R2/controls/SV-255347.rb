control 'SV-255347' do
  title 'Azure SQL Database must only use approved firewall settings deemed by the organization to be secure, including denying azure services access to the server.'
  desc 'Use of nonsecure firewall settings, such as allowing azure services to access the server, exposes the system to avoidable threats.'
  desc 'check', 'Azure SQL Database must only use approved firewall settings, including denying access to azure services and resources to the server. This option is denied by default in Azure SQL Database and should be left disabled if not otherwise documented and approved.

Obtain a list of approved firewall settings from the database documentation.
 
Verify that the "Allow Azure services and resources to access this server" option is disabled.
1. From the Azure Portal, navigate to the Azure SQL Database Dashboard.
2. Select "Set Server Firewall" on the top menu.
3. Under "Exceptions", review the "Allow Azure services and resources to access this server" option and verify that the value is not checked.

If the "Allow Azure services and resources to access this server" option is enabled, it must be necessary and specifically approved in the database documentation, otherwise this is a finding.'
  desc 'fix', 'Assign the approved policy to Azure SQL Database.
1. From the Azure Portal Dashboard, click "Set Server Firewall".
2. Review the Allow Azure services and resources to access this server option.
3. Uncheck the box to "Deny Azure" services and resources to access this server.
4. Click "Save".

For more information about connection policies:
https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59020r877261_chk'
  tag severity: 'medium'
  tag gid: 'V-255347'
  tag rid: 'SV-255347r879756_rule'
  tag stig_id: 'ASQL-00-011950'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-58964r871166_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
