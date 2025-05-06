control 'SV-77277' do
  title 'If TLS optimization is used, the Riverbed Optimization System (RiOS) providing Signed SMB and/or Encrypted MAPI must ensure the integrity and confidentiality of data transmitted over the WAN.'
  desc 'Protecting the end-to-end security of TLS is required to ensure integrity and confidentiality of the data in transit.

Signed SMB and encrypted MAPI traffic use techniques to protect against unauthorized man-in-the-middle devices from making modifications to their exchanged data. Additionally, encrypted MAPI traffic and encrypted SMB3 traffic ensure data confidentiality by transmitting data with protection across the network. 

To securely optimize this traffic, a properly configured client and server-side SteelHead appliance with the SteelHead WAN optimization platform must:

- decrypt and remove signatures on received LAN side data from the client or server.
- perform bandwidth and application layer optimization.
- use the secure inner channel feature to maintain data integrity and confidentiality of data transmitted over the WAN.
- convert the received optimized data back to its native form.
- encrypt and apply signatures for LAN side transmission of data to the client or server.

To query the Windows domain controller for the necessary cryptographic information to optimize this traffic, the server-side SteelHead appliance must join a Windows domain. The SteelHead appliance can require other configurations, both on the SteelHead appliance, and in the Windows domain. This cryptographic information is only useful for the lifetime of an individual connection or session. The information is obtained at the beginning of a connection, and transferred to the client-side SteelHead appliance as needed, using the secure inner channel feature. You must configure the secure inner channel to ensure maximum security.

Only the server-side SteelHead appliance is required to join the domain, and it does so using a machine account in the same way that a Windows device joins the domain using a machine account. The SteelHead appliance joins the domain this way to obtain a client user session key (CUSK) or server user session key (SUSK), which allows the SteelHead appliance to sign and/or decrypt MAPI on behalf of the Windows user that is establishing the relevant session.

The server-side SteelHead appliance must join a domain that is either: 
- the user domain. The domain must have a trust with the domains that include the application servers (file server, Exchange server, and so on) you want to optimize.
- A domain with a bi-directional trust with the user domain. The domain might include some or all of the Windows application servers (file server, Exchange server) for SteelHead appliance optimization. Production deployments can have multiple combinations of client and server Windows operating system versions, and can include different configuration settings for signed SMB and encrypted MAPI. NTLM is not approved for use for DoD implementations. Therefore it is possible that the security authentication between clients and servers can use Kerberos, or a combination of the two.'
  desc 'check', 'Verify the RiOS providing Signed SMB and Encrypted MAPI optimization services is configured to ensure the integrity and confidentiality of data transmitted over the WAN.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> Windows Domain Auth
Verify that a Domain is defined under "Kerberos"
Navigate to Configure >> Optimization >> CIFS (SMB1).
Verify that "Enable SMB Signing", "NTLM Delegation Mode", and "Enable Kerberos Authentication Support" are selected.

Navigate to Configure >> Optimization >> SMB2/3.
Verify that "Enable SMB2 and SMB3 Signing", "NTLM Delegation Mode", and "Enable Kerberos Authentication Support" are selected.

Navigate to Configure >> Optimization >> MAPI.
Verify that "Enable Encrypted Optimization", "NTLM Delegation Mode", and "Enable Kerberos Authentication Support" are selected.

If any SMB Signing or Encrypted MAPI is selected and the status of "In Domain Mode, Status: In a Domain" is not displayed, this is a finding.'
  desc 'fix', 'On the Server-Side SteelHead appliance Navigate to the device Management Console.

Navigate to Configure >> Optimization >> Windows Domain Auth
Under Kerberos select "Add a New User"
Enter the "Active Directory Domain Name".
Enter the UserID in "Domain Login:".
Enter the User Account Password in "Password".
Enter "Password Confirm"
Select "Enable RODC Password Replication Policy"
Enter the "Domain Controller Name(s):" or IP Addresses.
Click "Add".
Verify that "In Domain Mode, Status: In a Domain" is displayed on the page.

Navigate to Configure >> Optimization >> CIFS (SMB1).
Select "Enable SMB Signing"
Select "NTLM Delegation Mode"
Select "Enable Kerberos Authentication Support".
Click "Apply"

Navigate to Configure >> Optimization >> SMB2/3.
Select "Enable SMB2 and SMB3 Signing"
Select "NTLM Delegation Mode"
Select "Enable Kerberos Authentication Support".
Click "Apply".

Navigate to Configure >> Optimization >> MAPI.
Select "Enable Encrypted Optimization"
Select "NTLM Delegation Mode"
Select "Enable Kerberos Authentication Support".
Click "Apply".

Navigate to the top of the web page and click "Save" to save these setting permanently.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62787'
  tag rid: 'SV-77277r1_rule'
  tag stig_id: 'RICX-AG-000032'
  tag gtitle: 'SRG-NET-000521-ALG-000002'
  tag fix_id: 'F-68707r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
