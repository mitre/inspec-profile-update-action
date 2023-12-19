control 'SV-96147' do
  title 'Citrix Windows Virtual Delivery Agent must implement DoD-approved encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'NOTE: If an approved DoD VPN or proxy device is used for external connections, this requirement is Not Applicable.

Verify TLS Certificate is installed in the Local Computer >> Personal >> Certificates area of the certificate store.

1. Launch the Microsoft Management Console (MMC): Start >> Run >> mmc.exe.
2. Add the Certificates snap-in to the MMC:
- Select File >> Add/Remove Snap-in.
- Select "Certificates" and then click "Add".
3. When prompted with "This snap-in will always manage certificates for:" choose "Computer account" and then click "Next".
4. When prompted with "Select the computer you want this snap-in to manage", choose "Local computer" and then click "Finish".
5. Under Certificates (Local Computer) >> Personal >> Certificates, right-click the certificate and then select All Tasks >> Manage Private Keys.
6. The Access Control List Editor displays "Permissions for (FriendlyName) private keys" where (FriendlyName) is the name of the SSL certificate. Verify one of the following services is listed with Read access:
- For a VDA for Windows Desktop OS, "PORTICASERVICE"
- For a VDA for Windows Server OS, "TERMSERVICE"

If one of the associated services is not listed with "Read" access, this is a finding.'
  desc 'fix', %q(Configure TLS on a VDA using the PowerShell script:
Install the TLS Certificate in the Local Computer >> Personal >> Certificates area of the certificate store. 
If more than one certificate resides in that location, supply the thumbprint of the certificate to the PowerShell script.

The "Enable-VdaSSL.ps1" script enables or disables the TLS listener on a VDA. This script is available in the Support >> Tools >> SslSupport folder on the installation media.

When you enable TLS, the script disables all existing Windows Firewall rules for the specified TCP port. It then adds a new rule that allows the ICA Service to accept incoming connections only on the TLS, TCP, and UDP ports. It also disables the Windows Firewall rules for:
- Citrix ICA (default: 1494)
- Citrix CGP (default: 2598)
- Citrix WebSocket (default: 8008)

The effect is that users can only connect using TLS or DTLS. They cannot use ICA/HDX, ICA/HDX with Session Reliability, or HDX over WebSocket without TLS or DTLS.

The PowerShell script configures TLS on static VDAs; it does not configure TLS on pooled VDAs that are provisioned by Machine Creation Services or Provisioning Services, where the machine image resets on each restart.

Manually configure TLS on a VDA: 
When configuring TLS on a VDA manually, you grant generic read access to the TLS certificate's private key for the appropriate service on each VDA: NT SERVICE\PorticaService for a VDA for Windows Desktop OS, or NT SERVICE\TermService for a VDA for Windows Server OS. 

On the machine where the VDA is installed:
1. Launch the Microsoft Management Console (MMC): Start >> Run >> mmc.exe.
2. Add the Certificates snap-in to the MMC:
a) Select File >> Add/Remove Snap-in.
b) Select "Certificates" and then click "Add".
c) When prompted with "This snap-in will always manage certificates for:" choose "Computer account" and then click "Next".
d) When prompted with "Select the computer you want this snap-in to manage", choose "Local computer" and then click "Finish".
3. Under Certificates (Local Computer) >> Personal >> Certificates, right-click the certificate and then select All Tasks >> Manage Private Keys.
4. The Access Control List Editor displays "Permissions for (FriendlyName) private keys" where (FriendlyName) is the name of the TLS certificate. Add one of the following services and give it Read access:
- For a VDA for Windows Desktop OS, "PORTICASERVICE"
- For a VDA for Windows Server OS, "TERMSERVICE"
5. Double-click the installed TLS certificate. In the certificate dialog, select the "Details" tab and then scroll to the bottom. Click "Thumbprint".
6. Run "regedit" and go to "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\icawd".
a) Edit the SSL Thumbprint key and copy the value of the TLS certificate's thumbprint into this binary value. You can safely ignore unknown items in the Edit Binary Value dialog box (such as "0000" and special characters).
b) Edit the SSLEnabled key and change the DWORD value to "1". (To disable SSL later, change the DWORD value to "0".)
c) To change the default settings (optional), use the following in the same registry path:
SSLPort DWORD – SSL port number. Default: 443.
SSLMinVersion DWORD – 1 = SSL 3.0, 2 = TLS 1.0, 3 = TLS 1.1, 4 = TLS 1.2. Default: 2 (TLS 1.0).
SSLCipherSuite DWORD – 1 = GOV, 2 = COM, 3 = ALL. Default: 3 (ALL).
7. Ensure the TLS TCP port is open in the Windows Firewall if it is not the default "443". (When creating the inbound rule in Windows Firewall, make sure its properties have the "Allow the connection" and "Enabled" entries selected.)
8. Ensure that no other applications or services (such as IIS) are using the TLS TCP port.
9. For VDAs for Windows Server OS, restart the machine for the changes to take effect. (You do not need to restart machines containing VDAs for Windows Desktop OS.)

Configure TLS on Delivery Groups:
Complete this procedure for each Delivery Group that contains VDAs that have been configured for TLS connections.
1. From "Studio", open the PowerShell console.
2. Run "asnp Citrix.*" to load the Citrix product cmdlets.
3. Run the following command
Get-BrokerAccessPolicyRule -DesktopGroupName '<delivery-group-name>' | Set-BrokerAccessPolicyRule -HdxSslEnabled $true.
4. Run the following command
Set-BrokerSite -DnsResolutionEnabled $true.)
  impact 0.7
  ref 'DPMS Target XenDesktop 7.x VDA-Windows'
  tag check_id: 'C-81173r2_chk'
  tag severity: 'high'
  tag gid: 'V-81433'
  tag rid: 'SV-96147r2_rule'
  tag stig_id: 'CXEN-VD-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-88251r2_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000015', 'SRG-APP-000039', 'SRG-APP-000219', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001184', 'CCI-001414', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'SC-23', 'AC-4', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
