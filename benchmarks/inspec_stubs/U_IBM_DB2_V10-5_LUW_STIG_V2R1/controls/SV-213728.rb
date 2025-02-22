control 'SV-213728' do
  title 'DB2 must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate.  PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability.

This requirement focuses on communications protection for the DBMS session rather than for the network packet.'
  desc 'check', 'Run the following command to find certificate details: 

     $gsk8capicmd_64 -cert -details -db "<mydbserver.kdb>" -pw "<PASSWORD>" -label "<myselfsigned>"

The output is displayed in  a form similar to the following: 

-- label : myselfsigned key size : 1024 version : X509 V3 serial : 96c2db8fa769a09d

-- issue:CN=myhost.mycompany.com,O=myOrganization,OU=myOrganizationUnit,
L=myLocation,ST=ON,C=CA 

-- subject:CN=myhost.mycompany.com,O=myOrganization,OU=myOrganizationUnit,
L=myLocation,ST=ON,C=CA not before : Tuesday, 24 February 2009 17:11:50 PM not after : Thursday, 25 February 2010 17:11:50 PM

If the certificate is not issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs), this is a finding.'
  desc 'fix', %q(Create a key database and set up the digital certificates.

The following command creates a key database called mydbserver.kdb and a stash file called mydbserver.sth: 

     $gsk8capicmd_64 -keydb -create -db "mydbserver.kdb" -pw "myServerPassw0rdpw0" -stash

When you create a key database, it is automatically populated with signer certificates from a few certificate authorities (CAs), such as Verisign.

Add a certificate for your server to your key database. 

To obtain a certificate, you can either use GSKCapiCmd to create a new certificate request and submit it to a CA to be signed, or you can create a self-signed certificate for testing purposes. 

Following is an example of command to create a self-signed certificate with a label of myselfsigned, use the GSKCapiCmd command as shown in the following command:

     $gsk8capicmd_64 -cert -create -db "mydbserver.kdb" -pw "myServerPassw0rdpw0" -label "myselfsigned" -dn "CN=myhost.mycompany.com,O=myOrganization, OU=myOrganizationUnit,L=myLocation,ST=ON,C=CA"

Notes:

-- Use the GSKCapiCmd tool to create the key database. It must be a Certificate Management System (CMS) type key database. 

The GSKCapiCmd is a non-Java-based command-line tool, and Java does not need to be installed on the system to use this tool. 

You invoke GSKCapiCmd using the GSKCAPICMD command, as described in the GSKCapiCmd User's Guide. 

The path for the command is sqllib/gskit/bin on Linux and UNIX platforms, and C:\Program Files\IBM\GSK8\bin on both 32-bit and 64-bit Windows platforms. 

On 64-bit platforms, the 32-bit GSKit executable files and libraries are also present; in this case, the path for the command is C:\ProgramFiles (x86)\IBM\GSK8\bin. - Ensure PATH (on the Windows platform) includes the proper GSKit library path, and LIBPATH, SHLIB_PATH, or LD_LIBRARY_PATH (on UNIX or Linux platforms) include the proper GSKit library path, such as sqllib/lib64/gskit.
The -stash option creates a stash file at the same path as the key database, with a file extension of .sth. At instance start-up, GSKit uses the stash file to obtain the password to the key database.
To extract the certificate you created to a file, so that you can distribute it to computers running clients that will be establishing SSL connections to your DB2 server.

Run the following GSKCapiCmd command extracts the certificate to a file called mydbserver.arm:

     $gsk8capicmd_64 -cert -extract -db "mydbserver.kdb" -pw "myServerPassw0rdpw0" -label "myselfsigned" -target "mydbserver.arm" -format ascii –fips)
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14949r295233_chk'
  tag severity: 'medium'
  tag gid: 'V-213728'
  tag rid: 'SV-213728r879798_rule'
  tag stig_id: 'DB2X-00-008700'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-14947r295234_fix'
  tag 'documentable'
  tag legacy: ['SV-89273', 'V-74599']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
