control 'SV-214042' do
  title 'The SQL Server Browser service must be disabled unless specifically required and approved.'
  desc 'The SQL Server Browser simplifies the administration of SQL Server, particularly when multiple instances of SQL Server coexist on the same computer. It avoids the need to hard-assign port numbers to the instances and to set and maintain those port numbers in client systems. It enables administrators and authorized users to discover database management system instances, and the databases they support, over the network. SQL Server uses the SQL Server Browser service to enumerate instances of the Database Engine installed on the computer. This enables client applications to browse for a server, and helps clients distinguish between multiple instances of the Database Engine on the same computer.

This convenience also presents the possibility of unauthorized individuals gaining knowledge of the available SQL Server resources. Therefore, it is necessary to consider whether the SQL Server Browser is needed. Typically, if only a single instance is installed, using the default name (MSSQLSERVER) and port assignment (1433), the Browser is not adding any value. The more complex the installation, the more likely SQL Server Browser is to be helpful. 

This requirement is not intended to prohibit use of the Browser service in any circumstances.  It calls for administrators and management to consider whether the benefits of its use outweigh the potential negative consequences of it being used by an attacker to browse the current infrastructure and retrieve a list of running SQL Server instances.'
  desc 'check', 'If the need for the SQL Server Browser service is documented and authorized, this is not a finding. 

Open the Services tool. 

Either navigate, via the Windows Start Menu and/or Control Panel, to "Administrative Tools", and select "Services"; or at a command prompt, type "services.msc" and press the "Enter" key. 

Scroll to "SQL Server Browser". 

If its Startup Type is not shown as "Disabled", this is a finding.'
  desc 'fix', 'If SQL Server Browser is needed, document the justification and obtain the appropriate authorization. 

Where SQL Server Browser is judged unnecessary, the Service can be disabled. 

To disable, in the Services tool, double-click "SQL Server Browser". Set "Startup Type" to "Disabled". If "Service Status" is "Running", click on "Stop". Click on "OK".'
  impact 0.3
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15259r313909_chk'
  tag severity: 'low'
  tag gid: 'V-214042'
  tag rid: 'SV-214042r879887_rule'
  tag stig_id: 'SQL6-D0-017800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-15257r313910_fix'
  tag 'documentable'
  tag legacy: ['SV-94055', 'V-79349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
