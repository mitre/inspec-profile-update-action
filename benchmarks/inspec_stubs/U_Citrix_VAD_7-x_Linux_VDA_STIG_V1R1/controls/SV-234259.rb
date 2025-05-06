control 'SV-234259' do
  title 'Citrix Linux Virtual Delivery Agent (LVDA) must be configured to prohibit or restrict the use of ports, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'On Delivery Controllers, verify that only approved ports are used. 

1. Open a command prompt.
2. Navigate to the Citrix install directory Program Files\\Citrix\\Broker\\Service
3. Enter "BrokerService.exe /Show" to display the currently used ports.

If an unapproved port is used, this is a finding.'
  desc 'fix', 'To change the VDA registration port from the default "80", create the Citrix Machine Policy and update the DDCs, as explained below:
1. Create a new Citrix Machine policy or edit an existing one.
2. Navigate to the Settings tab and select "Control Registration Port".
3. Update the Value to reflect the new port.
4. Select "OK".
5. Restart all desktops and wait until all the desktops report as Unregistered.
6. Update the DDCs VDA registration Port.
7. Restart all desktops and verify that all VDAs register successfully.'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x LVDA'
  tag check_id: 'C-37444r612331_chk'
  tag severity: 'medium'
  tag gid: 'V-234259'
  tag rid: 'SV-234259r628796_rule'
  tag stig_id: 'LVDA-VD-000275'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-37409r612332_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
