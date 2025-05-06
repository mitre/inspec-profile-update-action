control 'SV-53287' do
  title 'SQL Server must support the organizational requirements to specifically prohibit or restrict the use of unauthorized functions, ports, protocols, and/or services.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Additionally, it is sometimes convenient to provide multiple services from a single component of an information system (e.g., email and web services) but doing so increases risk over limiting the services provided by any one component.  

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and, through the database, to other components of the information system.

For detailed guidance on Ports, Protocols, and Services Management (PPSM), refer to the PPSM section of the Information Assurance Support Environment (IASE) web site, at http://iase.disa.mil/ppsm/Pages/index.aspx.'
  desc 'check', 'Review the SQL Server configuration and settings for functions, ports, protocols, and services that are not approved or are not used, but are available.

To determine the protocol(s) enabled for SQL Server, open SQL Server Configuration Manager.  In the left-hand pane, expand SQL Server Network Configuration.  Click on the entry for the SQL Server instance under review:  "Protocols for <instance name>".  The right-hand pane displays the protocols enabled for the instance.

To determine whether SQL Server is configured to use a fixed port or dynamic ports, in the right-hand pane double-click on the TCP/IP entry, to open the Properties dialog.  (The default fixed port is 1433.)

To see which ports are open on the server, run netstat-a from a Windows command prompt.

If any ports, protocols, and/or services that are not approved or are not used, are available, this is a finding.'
  desc 'fix', 'Disable functions, ports, protocols, and services that are not approved or are not used, but are enabled.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47588r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40933'
  tag rid: 'SV-53287r3_rule'
  tag stig_id: 'SQL2-00-017400'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-46215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
