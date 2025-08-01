control 'SV-251420' do
  title 'The Ivanti MobileIron Core server must use a FIPS-validated cryptographic module to generate cryptographic hashes.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard.

The cryptographic module used must have at least one validated hash algorithm. This validated hash algorithm must be used to generate cryptographic hashes for all cryptographic security function within the product being evaluated.

'
  desc 'check', 'On the MDM console, do the following:
1. SSH to MobileIron Core Server from any SSH client.
2. Enter the administrator credentials you set when you installed MobileIron Core.
3. Enter show fips.
4. Verify "FIPS 140 mode is enabled" is displayed.

If the MobileIron Server Core does not report that FIPS mode is enabled, this is a finding.'
  desc 'fix', 'Configure the MDM server to use a FIPS 140-2 validated cryptographic module.

On the MDM console, do the following:
1. SSH to MobileIron Core Server from any SSH client.
2. Enter the administrator credentials you set when you installed MobileIron Core.
3. Enter enable.
4. When prompted, enter the enable secret you set when you installed MobileIron Core.
5. Enter configure terminal.
6. Enter the following command to enable FIPS: fips
7. Enter the following command to proceed with the necessary reload: do reload'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54855r806390_chk'
  tag severity: 'high'
  tag gid: 'V-251420'
  tag rid: 'SV-251420r806392_rule'
  tag stig_id: 'IMIC-11-012400'
  tag gtitle: 'SRG-APP-000514-UEM-000389'
  tag fix_id: 'F-54808r806391_fix'
  tag satisfies: ['FCS_COP.1.1(2)']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
