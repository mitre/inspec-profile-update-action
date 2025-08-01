control 'SV-251423' do
  title 'The Ivanti MobileIron Core server must be configured to implement FIPS 140-2 mode for all server and agent encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

A block cipher mode is an algorithm that features the use of a symmetric key block cipher algorithm to provide an information service, such as confidentiality or authentication.

AES is the FIPS-validated cipher block cryptographic algorithm approved for use in DoD. For an algorithm implementation to be listed on a FIPS 140-2 cryptographic module validation certificate as an approved security function, the algorithm implementation must meet all the requirements of FIPS 140-2 and must successfully complete the cryptographic algorithm validation process. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3, CCM, GCM, KW, KWP, and TKW.

'
  desc 'check', 'On the MDM console, do the following:
1. SSH to MobileIron Core Server from any SSH client.
2. Enter the administrator credentials you set when you installed MobileIron Core.
3. Enter show fips.
4. Verify "FIPS 140 mode is enabled" is displayed.
5. If the MobileIron Server Core does not report that FIPS mode is enabled, this is a finding.'
  desc 'fix', 'Configure the MDM server to use a FIPS 140-2 validated cryptographic module.

On the MDM console, do the following:
1. SSH to MobileIron Core Server from any SSH client.
2. Enter the administrator credentials you set when you installed MobileIron Core.
3. Enter enable.
4. When prompted, enter the enable secret you set when you installed MobileIron Core.
5. Enter configure terminal.
6. Enter the following command to enable FIPS: fips
7. Enter the following command to proceed with the necessary reload: do reload.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54858r806399_chk'
  tag severity: 'high'
  tag gid: 'V-251423'
  tag rid: 'SV-251423r806401_rule'
  tag stig_id: 'IMIC-11-012800'
  tag gtitle: 'SRG-APP-000555-UEM-000393'
  tag fix_id: 'F-54811r806400_fix'
  tag satisfies: ['FCS_COP.1.1(1)', 'FTP_TRP.1.1(1)  \nReference: PP-MDM-414001']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
