control 'SV-254099' do
  title 'Nutanix AOS must implement cryptography mechanisms to protect the confidentiality and integrity of the remote access session.'
  desc 'Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the application server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

Application servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using ssh or some other form of approved cryptography. Application servers must have a capability to enable a secure remote admin capability.

FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.

'
  desc 'check', 'Validate that the Signing Algorithm of the current SSL certificate.

In the Prism UI, click the gear icon, and then select Settings >> SSL Certificate.

If there is no SSL Certificate loaded, this is a finding.'
  desc 'fix', 'Import a DoD PKI issued SSL Certificate by Following the "Install an SSL Certificate" instructions in the "AOS Security Guide" located on the Nutanix Portal or by completing the following steps.

1. Click the gear icon in the main menu, and then select SSL Certificate in the Settings page. The SSL Certificate dialog box appears.
2. To replace (or install) a certificate, click "Replace Certificate".
3. To apply a custom certificate that the user provides:
     a. Click the Import Key and Certificate option, and then click "Next".
     b. Complete the fields as follows, and then click the "Import Files". Note: All three imported files for the custom certificate must be PEM encoded.
          i. Private Key Type: Select the appropriate type for the signed certificate from the pull-down list (RSA 4096 bit, RSA 2048 bit, EC DSA 256 bit, EC DSA 384 bit, or EC DSA 521).
         ii. Private Key: Click "Browse", and then select the private key associated with the certificate to be imported.
        iii. Public Certificate: Click "Browse", and then select the signed public portion of the server certificate corresponding to the private key.
        iv. CA Certificate/Chain: Click "Browse", and then select the certificate or chain of the signing authority for the public certificate.

Use the "cat" command to concatenate a list of CA certificates into a chain file.

$ cat signer.crt inter.crt root.crt > server.cert'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57584r846383_chk'
  tag severity: 'high'
  tag gid: 'V-254099'
  tag rid: 'SV-254099r858120_rule'
  tag stig_id: 'NUTX-AP-000040'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-57535r858120_fix'
  tag satisfies: ['SRG-APP-000014-AS-000009', 'SRG-APP-000015-AS-000010']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)', 'AC-17 (2)']
end
