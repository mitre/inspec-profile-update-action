control 'SV-234565' do
  title 'Citrix Delivery Controller must implement DoD-approved encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'Enforcement is via TLS encryption. To verify, open the Registry Editor on each Delivery Controller and find the following key name: HKEY_LOCAL_MACHINE\\SOFTWARE\\Citrix\\DesktopServer 

1. Verify that the XmlServicesSslPort registry key exists with the correct value for SSL port. By default, it is set to "443".
2. Verify XmlServicesEnableNonSsl is set to "0".
3. Verify the corresponding registry value to ignore HTTPS traffic, XmlServicesEnableSsl, is not set to "0".

If "XmlServicesSslPort" is not set to the desired port, this is a finding.

If "XmlServicesEnableNonSsl" is not set to "0", this is a finding.

If XmlServicesEnableSsl is not set to "1", this is a finding.

To verify the FIPS Cipher Suites used:
1. From the Group Policy Management Console, go to Computer Configuration >> Administrative Templates >> Networks >> SSL Configuration Settings.
2. Double-click "SSL Cipher Suite Order" and verify the "Enabled" option is checked. 
3. Verify the correct Cipher Suites are listed in the correct order per current DoD guidelines.

If the "Enabled" option is not checked or the correct Cipher Suites are not listed in the correct order per current DoD guidelines, this is a finding.'
  desc 'fix', 'Obtain and install root certificate(s) for server certificates installed on VDAs, SQL Server(s), Storefront, and VM Host (VMware VCenter, Hyper-V, XenServer).

To install a TLS server certificate on the Delivery Controller without IIS:
1. Log on to each Delivery Controller with a domain account that has Administrator rights.
2. Obtain a TLS server certificate and install it on the Delivery Controller, and assign it to a port using netsh, using Microsoft server instructions.
3. Configure the Delivery Controller with the certificate.

To install a TLS server certificate on the Delivery Controller with IIS:
1. Add the server certificate per the Microsoft server instructions.
2. From IIS Manager, select the IIS site on which HTTPS will be enabled and select "Bindings" under "Edit Site".
3. Click "Add", select "Type" as https, and port number as "443". Select the SSL Certificate that was installed and click "OK".

To configure the Delivery Controller to use the no configured TLS port:
1. Change the XML TLS service port use the following command:
BrokerService –WiSslPort <port number>
2. Open the Registry Editor on the CVAD Controller and find the following key name:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Citrix\\DesktopServer
3. Verify that the "XmlServicesSslPort" DWORD value exists with the correct value for SSL port. By default, it is set to "443". If it does not exist, add it.
4. Verify that the "XmlServicesEnableSsl" DWORD value exists and is set to "1". If it does not exist, add it.
5. Reboot the Delivery Controller to ensure all changes take effect.

Perform the following only after ensuring all references to the Delivery Controllers on StoreFront servers and gateway proxy devices are set to use https and working. This includes STA references. Now disable non-TLS communication with the XML port.
1. Open the Registry Editor on the CVAD Controller and find the following key name:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Citrix\\DesktopServer
2. Add the DWORD value "XmlServicesEnableNonSsl" and set it to "1".
3. Reboot the Delivery Controller.

If XmlServicesEnableSsl is not set to "1", this is a finding.

Notes:
If the XML service port number on the Delivery Controller needs to be changed, update the IIS port number as well under "Bindings" to match the new value.

To change the default VDA registration port:
1. Log on to the Delivery Controller server with a domain account that has Administrator rights.
2. Open the command prompt window and type these commands:
%SystemDrive%
Cd %ProgramFiles%\\Citrix\\Broker\\Service
BrokerService.exe –VDAport 8888
3. Launch Server Manager from the Start menu.
4. In the Server Manager, go to the "Local Server" properties window and edit the "Windows Firewall" setting. Click "Advanced Settings".
5. Click "Inbound Rules".
6. Create a new inbound rule with the following settings:
a) In the Rule type screen, click "Port". Click "Next".
b) In the Protocol and Ports screen, select "Specific local ports" and type "8888". Click "Next".
c) In the Action screen, accept the default value "Allow the connection" and click "Next".
d) In the Profile screen, accept the default values and click "Next".
e) In the Name screen, type a name for the rule (example: Citrix VDA Registration Port) and click "Finish".

For correct Cipher Suite order per DoD guidance:
Apply the following to Computers OU containing CVAD infrastructure:
- XD2017 CC - Computer - SSL Ciphersuite Order

To configure the SSL Cipher Suite Order Group Policy setting manually, follow these steps:
1. At a command prompt, enter "gpedit.msc", and press "Enter". The Local Group Policy Editor is displayed.
2. Go to Computer Configuration >> Administrative Templates >> Network >> SSL Configuration Settings.
3. Under SSL Configuration Settings, select "SSL Cipher Suite Order".
4. In the SSL Cipher Suite Order pane, scroll to the bottom. Follow the instructions that are labeled "How to modify this setting".'
  impact 0.7
  ref 'DPMS Target Citrix VAD 7.x Delivery Controller'
  tag check_id: 'C-37750r615785_chk'
  tag severity: 'high'
  tag gid: 'V-234565'
  tag rid: 'SV-234565r628794_rule'
  tag stig_id: 'CVAD-DC-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37715r615786_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000015', 'SRG-APP-000039', 'SRG-APP-000142', 'SRG-APP-000172', 'SRG-APP-000219', 'SRG-APP-000224', 'SRG-APP-000416', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442', 'SRG-APP-000514']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000382', 'CCI-001184', 'CCI-001188', 'CCI-001414', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'CM-7 b', 'SC-23', 'SC-23 (3)', 'AC-4', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'SC-13 b']
end
