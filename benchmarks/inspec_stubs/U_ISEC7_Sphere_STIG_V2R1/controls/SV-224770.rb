control 'SV-224770' do
  title 'Before establishing a local, remote, and/or network connection with any endpoint device, the ISEC7 EMM Suite must use a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the device.'
  desc 'Without device-to-device authentication, communications with malicious devices may be established. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk. Currently, DoD requires the use of AES for bidirectional authentication since it is the only FIPS-validated AES cipher block algorithm. 

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network; the Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to apply the requirement only to those limited number (and type) of devices that truly need to support this capability.'
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
    Verify the Keystore type is set to JavaKeystore PKCS12.

Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Using the dropdown menu for "sslProtocol", select TLSv1.2.
Select Update at the bottom of the page.
Restart the ISEC7 EMM Suite Web service.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26461r461566_chk'
  tag severity: 'medium'
  tag gid: 'V-224770'
  tag rid: 'SV-224770r505933_rule'
  tag stig_id: 'ISEC-06-001760'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-26449r461567_fix'
  tag 'documentable'
  tag legacy: ['V-97399', 'SV-106503']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
