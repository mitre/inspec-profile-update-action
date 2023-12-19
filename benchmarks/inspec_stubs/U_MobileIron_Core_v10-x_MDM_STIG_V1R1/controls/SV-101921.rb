control 'SV-101921' do
  title 'The MobileIron Core v10 server must be configured to implement FIPS 140-2 mode for all server encryption (if not automatically configured during server install).'
  desc 'Unapproved cryptographic algorithms cannot be relied on to provide confidentiality or integrity, and DoD data could be compromised as a result. The most common vulnerabilities with cryptographic modules are those associated with poor implementation. FIPS 140-2 validation provides assurance that the relevant cryptography has been implemented correctly. FIPS 140-2 validation is also a strict requirement for use of cryptography in the federal government for protecting unclassified data.

SFR ID: FCS'
  desc 'check', 'On the MDM console, do the following:
1. SSH to MobileIron Core Server from any SSH client.
2. Enter the administrator credentials you set when you installed MobileIron Core.
3. Enter "show fips".
4. Verify "FIPS 140 mode is enabled" is displayed.

If the MobileIron Server Core does not report that fips mode is "enabled", this is a finding.'
  desc 'fix', 'Configure the MDM server to use a FIPS 140-2-validated cryptographic module.

On the MDM console, do the following:
1. SSH to MobileIron Core Server from any SSH client.
2. Enter the administrator credentials you set when you installed MobileIron Core.
3. Enter "enable".
4. When prompted, enter the "enable secret" you set when you installed MobileIron Core.
5. Enter "configure terminal".
6. Enter the following command to enable FIPS: fips
7. Enter the following command to proceed with the necessary reload: do reload'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91819'
  tag rid: 'SV-101921r1_rule'
  tag stig_id: 'MICR-10-000640'
  tag gtitle: 'PP-MDM-314001'
  tag fix_id: 'F-98021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001145']
  tag nist: ['SC-13 (1)']
end
