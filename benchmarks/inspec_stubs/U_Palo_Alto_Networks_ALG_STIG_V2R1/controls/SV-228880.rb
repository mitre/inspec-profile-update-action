control 'SV-228880' do
  title 'The Palo Alto Networks security platform must inspect inbound and outbound FTP and FTPS communications traffic (if authorized) for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as FTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols. The device must be configured to inspect inbound and outbound FTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.'
  desc 'check', 'Go to Policies >> Decryption
If there are no configured Decryption Policies, this is a finding.

Ask the Administrator which Security Policy inspects authorized FTP traffic.
Go to Policies >> Security
Select the identified Security Policy.

If the "Profile" column does not display the "Antivirus Profile" symbol, this is a finding.

If the "Profile" column does not display the "Vulnerability Protection Profile" symbol, this is a finding.'
  desc 'fix', 'If FTP and FTPS is authorized, configure a security policy to allow it and inspect it.
Since Secure File Transfer Protocol is a form of FTP that adds TLS and SSL cryptographic protocols, it is necessary to decrypt TLS in order for the device to inspect the FTP stream.
Go to Policies >> Decryption
Select "Add".
In the "Decryption Policy Rule" window, complete the required fields.
In the "Name" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" or "Source User" fields.
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" or "Destination User" fields.
In the "Option" tab, select "Decrypt" as the Action.  Select the decryption profile.
In the "Type" field, there are three options; 
Select "SSL Forward Proxy to decrypt and inspect SSL/TLS traffic from internal users to outside networks".
Select "SSH Proxy to decrypt inbound and outbound SSH connections passing through the device".
Select "SSL Inbound Inspection to decrypt and inspect incoming SSL traffic".  Note: This decryption mode can only work if you have control on the internal server certificate to import the Key Pair on Palo Alto Networks Device.
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it.
In the "Security Policy Rule" window, complete the required fields.
In the "Name" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.
In the "User" tab, complete the "Source User" and "HIP Profile" fields.
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields.
In the "Applications" tab, either select the "Any" check box or add "ftp", "tftp", and "gridftp".  Configured filters and groups can be selected if the group includes these protocols.
In the "Actions" tab, select "allow".  
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Profile Setting" section; in each of the Profile fields, select the configured Profile.
Note: An Antivirus Profile and an Antispyware Profile are required.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31115r513935_chk'
  tag severity: 'medium'
  tag gid: 'V-228880'
  tag rid: 'SV-228880r557387_rule'
  tag stig_id: 'PANW-AG-000148'
  tag gtitle: 'SRG-NET-000512-ALG-000065'
  tag fix_id: 'F-31092r513936_fix'
  tag 'documentable'
  tag legacy: ['V-62641', 'SV-77131']
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
