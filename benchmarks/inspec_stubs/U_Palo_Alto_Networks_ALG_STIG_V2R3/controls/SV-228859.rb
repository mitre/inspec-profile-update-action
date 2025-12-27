control 'SV-228859' do
  title 'The Palo Alto Networks security platform being used for TLS/SSL decryption using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certificate Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-Approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. If the Palo Alto Networks security platform is  used for TLS/SSL decryption, configure the Palo Alto Networks security platform to only accept end entity certificates issued by DoD PKI or DoD-approved PKI CAs for the establishment of protected sessions.'
  desc 'check', 'If the Palo Alto Networks security platform is not used for TLS/SSL decryption, this is not applicable.

If the Palo Alto Networks security platform accepts non-DoD approved PKI end entity certificates, this is a finding.'
  desc 'fix', 'Import the intermediate CA certificates.

To load a CA certificate on the Palo Alto Networks firewall:
Go to Device >> Certificate Management >> Certificates
On the "Device Certificate" tab, select "Import".
In the "Import Certificate" window, complete the required information.
In the "Certificate Name" field, enter the name of the certificate.
In the "Certificate File" field, select "Browse", then browse to and select the appropriate file.
In the "File Format"  field, select "Base64 Encoded Certificate (PEM)".
Select "OK".

Create a Client Certificate Profile:
Go to Device >>Certificate Management>> Certificate Profile
Select "Add".
In the Certificate Profile, complete the required fields.
In the "Name" field, enter the name of the Certificate Profile.
In the "Username" field, select "Subject".
Note: The adjacent field will contain common-name.
Add all of the DoD Intermediate Certificates.
Select the "Use OCSP" check box.
Select the "Block session if certificate status is unknown" check box.
Select the "Block session if certificate status cannot be retrieved within timeout".

Create an Authentication Profile:
Go to Device >> Authentication Profile
Select, "Add".
In the "Authentication Profile" window, complete the required fields.
In the "Authentication" field, add either "RADIUS" or "LDAP" based on the local requirements. 
In the Server Profile filed, select the server profile for the authentication server.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31094r513872_chk'
  tag severity: 'medium'
  tag gid: 'V-228859'
  tag rid: 'SV-228859r831599_rule'
  tag stig_id: 'PANW-AG-000101'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-31071r513873_fix'
  tag 'documentable'
  tag legacy: ['V-62599', 'SV-77089']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
