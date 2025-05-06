control 'SV-16796' do
  title 'VI client sessions to the ESX Server are unencrypted.'
  desc 'User sessions with the ESX Server should be encrypted since transmitting data in plaintext may be viewed as it travels through the network. User sessions may be initiated from the VI client, Web Access, or through VirtualCenter. To encrypt session data, the sending component, such as a gateway or redirector, applies ciphers to alter the data before transmitting it. The receiving component uses a key to decrypt the data, returning it to its original form. To ensure the protection of the data transmitted to and from external network connections, ESX Server uses the 256-bit AES block encryption. ESX Server also uses 1024-bit RSA for key exchange. These encryption algorithms are the default for VI Client, VI Web Access, VirtualCenter sessions.'
  desc 'check', '1. Log into the VirtualCenter server using the VI Client.
2. Click Administration > VirtualCenter Management Server Configuration
    The VirtualCenter Management Server Configuration dialog appears.
3. Click SSL Settings in the left pane and enable Check host certificates checkbox.  Click OK.
If the Check host certificates checkbox is not checked, this is a finding.
4. Verify that the SSL certificates exist on the ESX Server.  On the ESX Server service console check the /etc/vmware/ssl/ directory for the certificates by performing the following:
 
# ls –lL /etc/vmware/ssl/

If the default ESX Server keys are present below, this is a finding.
rui.cert
rui.key

This directory should contain a DoD certificate and key only (server.crt and server.key) If this directory does not contain a DoD certificate and key file, then this is a finding.  If no valid DoD certificate and private key are present here this is a finding. This directory should contain a DoD certificate and key only (server.crt and server.key). Validate the certificate is listed in the InstallRoot3.12_SAG.pdf document. The DoD certificates that are listed in the InstallRoot3.12_SAG.pdf document are listed in Section 1, Appendix B. If the certificate is not listed here, this is a finding.

Note: The InstallRoot3.12_SAG.pdf document may have been replaced with a newer version.  If so, use the most current version listed on the DoD PKE site.

Note: The InstallRoot3.12 _SAG.pdf document can be downloaded from the following links:  (Note: These links may have changed since the release of the checklist.)

https://www.us.army.mil/suite/page/474113 

OR

https://www.us.army.mil/suite/portal/index.jsp. Select Files and search for the InstallRoot folder.  Select the InstallRoot folder and select the InstallRoot3.12_SAG.pdf document to download.'
  desc 'fix', 'Enable encryption for all VI client sessions with the ESX Server.  To create DoD certificate and private key perform the following steps:
1. On the ESX Server, navigate to /usr/bin/ and execute the following command:                
 # openssl req –new –out filename.csr 
2.  When prompted enter the following: (Do not type the quotations)
	
For Country Name, type “US”
For State or Province Name, type “.”
For Locality Name, type “.”
For Organization Name, type “U.S. Government”
For Organizational Unit Name, type “OU=DISA, OU=PKI, OU=DoD”
For Common Name, type your Fully Qualified Domain Name of your server (i.e. server.disa.mil)
For Email Address, type your email address

3.  The output from this command will yield two files: filename.csr and privkey.pem 
4. Upload/Copy the filename.csr to the Regular SSL Server Enrollment Form for the DoD PKI site.  You may use either of the two sites below.

 Note: These Certificate Authorities may have been decommissioned since the release of the checklist. If so, please use the most current Certificate Authority for enrolling your certificate request.

CA-17 URL - https://ca-17.c3pki.chamb.disa.mil/ca
CA-18 URL - https://ca-18.c3pki.den.disa.mil/ca

5. You will be emailed that your certificate is ready and you will retrieve your signed certificate from the CA.
6. Put the new signed certificate and private key in the /etc/vmware/ssl/ directory. Move the old certificate and key from the directory and put them somewhere safe for backup purposes.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16204r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15855'
  tag rid: 'SV-16796r1_rule'
  tag stig_id: 'ESX0560'
  tag gtitle: 'VI client sessions to ESX Server are unencrypted.'
  tag fix_id: 'F-15809r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
