control 'SV-255334' do
  title 'The Azure SQL Database must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols/services on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and through the database to other components of the information system.'
  desc 'check', 'Azure SQL Database must only use approved firewall settings, including disabling public network access. This value is allowed by default in Azure SQL Database and must be disabled if not otherwise documented and approved.

Obtain a list of all approved firewall settings from the database documentation. 
 
From the Azure Portal Dashboard, click the database, then click "Set Server Firewall". Verify that the public network access option is set to disabled.

If the value is enabled and not specifically approved in the database documentation, this is a finding.'
  desc 'fix', 'Assign the approved policy to Azure SQL Database.
1. From the Azure Portal Dashboard, click the "database".
2. Click "Set Server Firewall".
3. Review the public network access option.
4. Check the box to "Disable" public network access.
5. Click "Save".

For more information about connection policies:
https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59007r871126_chk'
  tag severity: 'medium'
  tag gid: 'V-255334'
  tag rid: 'SV-255334r879588_rule'
  tag stig_id: 'ASQL-00-007700'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-58951r871127_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
