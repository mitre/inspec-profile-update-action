control 'SV-96141' do
  title 'Citrix Receiver must implement DoD-approved encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'Verify encryption has been enabled on devices running Citrix Receiver:

Open the Citrix Receiver Group Policy Object administrative template by running gpedit.msc.

1. Launch the Citrix Receiver Group Policy Object administrative template using the Group Policy Management Console.
2. Under the Computer Configuration node, go to Administrative Templates >> Citrix Receiver >> Network routing and select the TLS and Compliance Mode Configuration policy.
3. Verify the policy is enabled.

If the policy is not enabled, this is a finding.

4. Verify the following policy options are selected:
- Verify "Require TLS for all connections" is selected. 
- From the Security Compliance Mode drop-down, verify "SP800-52" is selected. 
- Verify "Full access check and CRL required" is selected.
- Verify "Enable FIPS: is selected.
- From the Allow TLS Servers drop-down, verify the desired port number is entered.
- Verify "TLS 1.2" is selected.
- From the TLS cipher suite drop-down, verify "Select Government (GOV)" is selected.
- From the Certificate Revocation Check Policy drop-down, select the policy required by your Organizational Security Policy.

If any of the policy options noted above are not selected, this is a finding.'
  desc 'fix', 'As an administrator, open the Citrix Receiver Group Policy Object administrative template by running gpedit.msc.

Apply the policy on a domain OU containing User Devices running Windows Receiver. 
1. Launch the Citrix Receiver Group Policy Object administrative template using the Group Policy Management Console.
2. Under the Computer Configuration node, go to Administrative Templates >> Citrix Receiver >> Network routing and select the TLS and Compliance Mode Configuration policy.
3. Select "Enabled" to enable secure connections and to encrypt communication on the server. Set the following options:
- Select "Require TLS" for all connections to force Citrix Receiver for Windows to use TLS for all connections to published applications and desktops.
- From the Security Compliance Mode drop-down, select the option:
SP800-52 – Select SP800-52 for compliance with NIST SP 800-52.
- Select Full access check and CRL required.
4. Enable FIPS - Select this option to enforce the use of FIPS-approved cryptography. You must also enable the Windows security option from the operating system group policy, System Cryptography: Use FIPS-compliant algorithms for encryption, hashing, and signing. Otherwise, Citrix Receiver for Windows might fail to connect to published applications and desktops.
5. From the Allow TLS Servers drop-down, select the port number. Ensure that Citrix Receiver connects only to a specified server by using a comma-separated list. Wildcards and port numbers can be specified. For example, *.citrix.com:4433 allows connections to any server whose common name ends with .citrix.com on port 4433. The issuer of the certificate asserts the accuracy of the information in a security certificate. If Citrix Receiver does not recognize and trust the issuer, the connection is rejected.
6. From the TLS version drop-down, select "TLS 1.2".
7. TLS cipher suite - Select "Government (GOV)"
8. From the Certificate Revocation Check Policy drop-down, select the policy required by the Organizational Security Policy.'
  impact 0.7
  ref 'DPMS Target XenDesktop 7.x Receiver'
  tag check_id: 'C-81167r1_chk'
  tag severity: 'high'
  tag gid: 'V-81427'
  tag rid: 'SV-96141r1_rule'
  tag stig_id: 'CXEN-RE-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-88243r1_fix'
  tag satisfies: ['SRG-APP-000014', 'SRG-APP-000015', 'SRG-APP-000142', 'SRG-APP-000219', 'SRG-APP-000416', 'SRG-APP-000427', 'SRG-APP-000439', 'SRG-APP-000440', 'SRG-APP-000441', 'SRG-APP-000442', 'SRG-APP-000514']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000382', 'CCI-001184', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-002450', 'CCI-002470']
  tag nist: ['AC-17 (2)', 'CM-7 b', 'SC-23', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)', 'SC-13 b', 'SC-23 (5)']
end
