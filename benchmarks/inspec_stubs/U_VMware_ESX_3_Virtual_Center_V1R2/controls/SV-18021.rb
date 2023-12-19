control 'SV-18021' do
  title 'VirtualCenter is not using DoD approved certificates.'
  desc 'User sessions with VirtualCenter should be encrypted since transmitting data in plaintext may be viewed as it travels through the network. User sessions may be initiated from the VI client and VI Web Access. To encrypt session data, the sending component, such as a gateway or redirector, applies ciphers to alter the data before transmitting it. The receiving component uses a key to decrypt the data, returning it to its original form. To ensure the protection of the data transmitted to and from external network connections, all VI client and web access sessions with VirtualCenter will be encrypted with a FIPS 140-2 encryption algorithm.'
  desc 'check', '1. Go to the following location to review the certificates on the VirtualCenter Server.
C:\\Documents and Settings\\All Users\\Application
Data\\VMware\\VMware VirtualCenter\\SSL\\

If no valid DoD certificate and private key are present here, this is a finding. This directory should contain a DoD certificate and key only (server.crt and server.key).  Validate the certificate is listed in the InstallRoot3.12_SAG.pdf document. The DoD certificates that are listed in the InstallRoot3.12_SAG.pdf document are listed in Section 1, Appendix B. If the certificate is not listed here, this is a finding.

Note: The InstallRoot3.12_SAG.pdf document may have been replaced with a newer version.  If so, use the most current version listed on the DoD PKE site.

Note: The InstallRoot3.12 _SAG.pdf document can be downloaded from the following links:  (Note: These links may have changed since the release of the checklist.)

https://www.us.army.mil/suite/page/474113 

OR

https://www.us.army.mil/suite/portal/index.jsp. 
Select Files and search for the InstallRoot folder.  Select the InstallRoot folder and select the InstallRoot3.12_SAG.pdf document to download.'
  desc 'fix', 'Employ signed DoD certificates on VirtualCenter.  
To create SSL/TLS certificates, the server administrator should use the site certificate ordering processes to obtain DoD PKI certficiates. Typically, the system administrator must use the Web Server or Web Server operating system tools as appropriate to generate the Public Key Cryptography Standard (PKCS) #10 certificate request. However, the following programs may be used to create and retrieve the signed certificate. 

1. Serveral programs are needed to create the openssl certificates. These include Activestate Perl, openssl for Win32, and Visual C++ 2008 Redistribute. To get these programs go to the following websites and download them: 

Note: These URL links may have changed since the release of the checklist.

a. Activestate Perl - Use http://www.activestate.com/activeperl/ and click on "ActivePerl Download Now".

b. Openssl for Win32 –  Use http://www.slproweb.com/products.htm

c. Visual C++ 2008 Redistribute - Use http://www.microsoft.com/downloads/details.aspx?familyid=9B2DA534-3E03-4391-8A4D-074B9F2BC1BF&displaylang=en

2. Navigate to the OpenSSL directory (c:\\openssl\\bin\\) on the VirtualCenter Server.
3. Generate the RSA key for the server and the certificate signing request (CSR):
openssl req -new -out filename.csr 

When prompted enter the following: (Do not type the quotations)

For Country Name, type “US”
For State or Province Name, type “.”
For Locality Name, type “.”
For Organization Name, type “U.S. Government”
For Organizational Unit Name, type “OU=DISA, OU=PKI, OU=DoD”
For Common Name, type your Fully Qualified Domain Name of your server (i.e. server.disa.mil)
For Email Address, type your email address

4.  The output from this command will yield two files: filename.csr and privkey.pem 
5. Upload/Copy the filename.csr to the Regular SSL Server Enrollment Form for the DoD PKI site.  You may use either of the two sites below.

Note: These Certificate Authorities may have been decommissioned since the release of the checklist. If so, please use the most current Certificate Authority for enrolling your certificate request.

CA-17 URL - https://ca-17.c3pki.chamb.disa.mil/ca
CA-18 URL - https://ca-18.c3pki.den.disa.mil/ca

6. You will be emailed that your certificate is ready and you will retrieve your signed certificate from the CA.
7. In addition, you must create a PFX-formatted certificate file specific for Windows. The filename.pfx file is a concatenation of the server’s certificate and private key, exported in the PFX format; this file is then copied to the sub-directory on the VirtualCenter Server. 
Perform the following command:  (filename is the name of your certificate file)

C:\\openssl\\bin\\Openssl pkcs12 –export in filename.crt –inkey privkey.pem –name filename –passout pass:testpassword –out filename.pfx

8. Put the new signed certificate, private key, and filename.pfx in the C:\\Documents and Settings\\All Users\\Application Data\\VMware\\VMware
VirtualCenter\\SSL\\ directory.  Move the old certificates from the directory and put them somewhere safe for backup purposes.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-17720r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17020'
  tag rid: 'SV-18021r1_rule'
  tag stig_id: 'ESX0725'
  tag gtitle: 'VirtualCenter does not use DoD approved certs.'
  tag fix_id: 'F-16829r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
