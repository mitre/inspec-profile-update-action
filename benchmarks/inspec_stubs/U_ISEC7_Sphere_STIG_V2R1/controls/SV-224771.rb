control 'SV-224771' do
  title 'The ISEC7 EMM Suite must allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Log in to the ISEC7 EMM Console.
Confirm that the browser session is secured using a DoD issued certificate. 

   Internet Explorer:
   Click on the Padlock icon at the end of the url field.
   Select View Certificates.
   Confirm that the Issued By is a valid DoD Certificate Authority.

   Google Chrome:
   Click on the Padlock icon at the front of the url field.
   Select Certificate.
   Confirm that the Issued By is a valid DoD Certificate Authority.

Alternately, Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Identify which type of Keystore is being used.

Windows MY:  
    Open the Microsoft Management Console.
    Add the Certificates Snap-In for the ISEC7 Service Account.
    Navigate to the Personal Certificates Store.
    Verify the certificate is issued by a DoD Trusted Certificate Authority.

JavaKeystore PKCS12:
    Using a Keystore browser such as Portecle, open the ISEC7 EMM Suite keystore.
    Enter the Keystore password when prompted.
    Open the installed certificate and verify it was issued by a DoD Trusted Certificate Authority.

If certificates used by the server are not DoD issued certificates, this is a finding.'
  desc 'fix', 'Submit a CSR for a DoD Issued Certificate with the private key.
Retrieve the approved certificate from the issuing Certificate Authority.
Set the friendly name on the certificate to https.

Windows-MY:
    Open the Microsoft Management Console.
    Add the Certificates Snap-In for the ISEC7 Service Account.
    Navigate to the Personal Certificates Store.
    Import the certificate with Private key.
    Log in to the ISEC7 EMM Console.
    Navigate to Administration >> Configuration >> Apache Tomcat Settings.
    Set the Keystore Type to Windows-MY.

JavaKeystore:
    Using a Keystore browser such as Portecle, open the ISEC7 EMM Suite keystore.
    Enter the Keystore password when prompted.
    Delete the self-signed certificate in the keystore.
    Import the DoD issued certificate with the private key.
    Enter the key password when prompted.
    Enter the certificate alias as https when prompted.
    Save the keystore with the same keystore password.
    Log in to the ISEC7 EMM Console.
    Navigate to Administration >> Configuration >> Apache Tomcat Settings.
    Verify the Keystore type is set to JavaKeystore PKCS12.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26462r461569_chk'
  tag severity: 'medium'
  tag gid: 'V-224771'
  tag rid: 'SV-224771r505933_rule'
  tag stig_id: 'ISEC-06-001960'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-26450r461570_fix'
  tag 'documentable'
  tag legacy: ['V-97401', 'SV-106505']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
