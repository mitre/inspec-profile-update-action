control 'SV-96123' do
  title 'Delivery Controller must implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the Federal Government since this provides assurance they have been tested and validated.'
  desc 'check', 'Enforcement is via FIPS encryption. To verify, open the Registry Editor on the XenDesktop Delivery Controller and find the following key name: HKEY_LOCAL_MACHINE\\SOFTWARE\\Citrix\\DesktopServer 

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
  desc 'fix', 'Obtain and install root certificate(s) for server certificates installed on Desktop/Server VDAs, SQL Server(s), Storefront, and VM Host (VMware VCenter, Hyper-V, XenServer).

To install a TLS server certificate on the Delivery Controller and to configure a port with TLS 1.x:
1. Log on to the Delivery Controller server with a domain account that has Administrator rights.
2. Obtain a TLS server certificate and install it on the Delivery Controller using Microsoft server instructions.
3. Configure the Delivery Controller with the certificate.

When the Server Certificate is installed on IIS, set the Bindings to enable HTTPS on IIS by completing the following procedure:
1. Select the IIS site that you want to enable HTTPS and select "Bindings" under "Edit Site".
2. Click "Add", select "Type" as https and port number as "443". Select the SSL Certificate that was installed and click "OK".
3. Open the Registry Editor on the XenDesktop Controller and find the following key name:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Citrix\\DesktopServer
4. Verify that XmlServicesSslPort registry key exists with the correct value for SSL port. By default, it is set to "443".
5. Change the XML service port using PowerShell or by running the following command:
BrokerService –WiSslPort <port number>

Notes:
a) If you decide to change the XML service port number on the XenDesktop controller, update the IIS port number as well under "Bindings" to match the new value.
b) On XenDesktop 7.11, the parameter of brokerservice.exe has changed from "wisslport" to "storefronttlsport". The brokerservice.exe is found in c:\\program files\\citrix\\broker\\service. 
A reboot of the Delivery Controller is needed for this to take effect.

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
e) In the Name screen, type a name for the rule (example: Citrix VDA Registration Port)
and click "Finish".

For correct Cipher Suite order per DoD guidance:
Apply the following to Computers OU containing XenDesktop infrastructure:
- XD2017 CC - Computer - SSL Ciphersuite Order

To configure the SSL Cipher Suite Order Group Policy setting manually, follow these steps:
1. At a command prompt, enter "gpedit.msc", and press "Enter". The Local Group Policy Editor is displayed.
2. Go to Computer Configuration >> Administrative Templates >> Network >> SSL Configuration Settings.
3. Under SSL Configuration Settings, select "SSL Cipher Suite Order".
4. In the SSL Cipher Suite Order pane, scroll to the bottom. Follow the instructions that are labeled "How to modify this setting".'
  impact 0.7
  ref 'DPMS Target XenDesktop 7.x Delivery Controller'
  tag check_id: 'C-81139r15_chk'
  tag severity: 'high'
  tag gid: 'V-81409'
  tag rid: 'SV-96123r2_rule'
  tag stig_id: 'CXEN-DC-001225'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-88215r4_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
