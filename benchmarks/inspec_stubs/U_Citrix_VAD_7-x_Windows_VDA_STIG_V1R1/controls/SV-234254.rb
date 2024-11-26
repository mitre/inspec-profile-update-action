control 'SV-234254' do
  title 'Citrix Windows Virtual Delivery Agent must be configured to prohibit or restrict the use of ports, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web service); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Some organizations consider port 80 to be a non-secure port regardless of the protocol. Ensure VDA registration traffic to the Delivery Controller is occurring on an approved port.

To verify the Delivery Controller is using an approved port, perform the following:
1. On each the Delivery Controller, open a command prompt.
2. Navigate to the Citrix install directory Program Files\\Citrix\\Broker\\Service.
3. Run the command "BrokerService.exe /Show" to display the currently used "VDA Port".
4. Ensure the port in use on each Delivery Controller matches and is approved by the DoD organization.

To verify the Windows VDA is using the approved port for registration, perform the following:
1. In Active Directory, open the Group Policy object used to apply VDA settings to the Windows VDA.
2. Navigate to Computer Configuration >> Policies >> Citrix Policies.
3. Edit the "Unfiltered Policy", or the custom policy used to apply Delivery Controller settings in the GPO.
4. Under the "Settings" tab, find the Virtual Delivery Agent Setting called "Controller registration port".
5. Ensure the port number matches the approved port set on the Delivery Controller.

If an unapproved port is used, this is a finding.'
  desc 'fix', 'Some organizations consider port 80 to be a non-secure port regardless of the protocol. It is necessary to set the Delivery Controller and VDAs to use an approved port for registration traffic.

To set the registration port on the broker to an approved port (e.g., 8080) perform the following:
1. On each the Delivery Controller, open a command prompt.
2. Navigate to the Citrix install directory Program Files\\Citrix\\Broker\\Service.
3. Run the command "BrokerService.exe -VDAPort 8080" to set the registration port to 8080. Replace 8080 with an approved port in the organization.
4. Run the command "BrokerService.exe /Show" to verify the VDA Port is changed.

To configure the Windows VDA to use the approved port set on the Delivery Controller, perform the following:
1. In Active Directory, open the Group Policy object used to apply VDA settings to the Windows VDA. If this GPO does not yet exist, create it.
2. Navigate to Computer Configuration >> Policies >> Citrix Policies.
3. Edit the "Unfiltered Policy” or create a custom Citrix policy to apply Delivery Controller settings in the GPO.
4. Under the "Settings" tab, find the Virtual Delivery Agent Setting called "Controller registration port".
5. Click "Add" to enable the setting and specify the approved port set on the Delivery Controller.
6. Ensure this GPO is linked to the OUs with the relevant Windows VDAs.'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x Windows VDA'
  tag check_id: 'C-37439r612305_chk'
  tag severity: 'medium'
  tag gid: 'V-234254'
  tag rid: 'SV-234254r628798_rule'
  tag stig_id: 'CVAD-VD-000275'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-37404r612306_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
