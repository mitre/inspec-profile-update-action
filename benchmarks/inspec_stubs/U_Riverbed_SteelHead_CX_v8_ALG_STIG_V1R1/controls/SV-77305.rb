control 'SV-77305' do
  title 'If TLS WAN optimization is used, Riverbed Optimization System (RiOS) providing SSL Optimization must protect private keys ensuring that they stay in the data center by ensuring end-to-end security.'
  desc 'Protecting the end-to-end security of TLS is required to ensure integrity and confidentiality of the data in transit.

The Riverbed Optimization System TLS optimization solution accelerates data transfers that are encrypted using TLS, provided SteelHead appliances that are deployed locally to both the client-side and server-side of the network. All of the same optimized connections that are applied to normal non-encrypted TCP traffic can also apply to encrypted TLS traffic. SteelHead appliances with RiOS accomplish this without compromising end-to-end security and the established trust model. Private keys remain in the data center and are not exposed in remote locations where they might be compromised.

The RiOS TLS optimization solution starts with SteelHead appliances that have a configured trust relationship, enabling them to exchange information securely over their own dedicated TLS connection. Each client uses unchanged server addresses and each server uses unchanged client addresses; no application changes or explicit proxy configuration is required. RiOS uses a unique technique to split the TLS handshake. The handshake is the sequence of message exchanges at the start of a TLS connection. In an ordinary TLS handshake, the client and server first establish identity using public-key cryptography, and then negotiate a symmetric session key to use for data transfer. When using RiOS TLS acceleration, the initial TLS message exchanges take place between the client application (for example, a Web browser) and the server side SteelHead appliance.

SteelHead WAN optimization platform works to ensure that TLS acceleration delivers the following:

- sensitive cryptographic information is kept in the secure vault - a separate, encrypted store on the disk.
- built-in support for popular Certificate Authorities (CAs) such as VeriSign, Thawte, Entrust, and GlobalSign. In addition, SteelHead appliances allow the installation of other commercial or privately operated CAs.
- import of server proxy certificates and keys in PEM, PKCS12, or DER formats. SteelHead appliances also support the generation of new keys and self-signed certificates. If your certificates and keys are in another format, you must first convert them to a supported format before you can import them into the SteelHead appliance.
- separate control of cipher suites for client connections, server connections, and peer connections.
- bulk export or bulk import server configurations (including keys and certificates) from or to, respectively, the server-side SteelHead appliance.'
  desc 'check', 'Verify that RiOS providing TLS optimization services is configured to ensure end-to-end security and protect private keys from unauthorized access.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> SSL Main Settings.
Verify that "Enable SSL Optimization" is checked.
Verify that "SSL Server Certificates:" contains the certificates for SSL services that the organization wants to optimize.

If "Enable SSL Optimization" is not checked or there are no "SSL Sever Certificates", this is a finding.'
  desc 'fix', 'Configure RiOS providing TLS optimization services to provide end-to-end security and protection for private keys.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> SSL Main Settings.
Navigate to SSL Server Certificates.
Select "Add a New SSL Certificate".
Select "Import Existing Private Key and CA-Signed Public Key".
Select "Local File".

Navigate to the certificate location on the management workstation and select the certificate for import.

Click "Add".
Navigate to "Enable SSL Optimization" and check the box.
Click "Apply".

Navigate to the top of the web page and click "Save" to save these setting permanently.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63609r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62815'
  tag rid: 'SV-77305r1_rule'
  tag stig_id: 'RICX-AG-000038'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-68733r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
