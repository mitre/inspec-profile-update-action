control 'SV-251036' do
  title 'The Sentry providing encryption intermediary services must implement NIST FIPS-validated cryptography to generate cryptographic hashes.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the Sentry uses encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions. 

On the MobileIron Sentry CLI console, do the following:
1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set when MobileIron Sentry was installed.
3. Enter "enable".
4. When prompted, enter the "enable secret" set when MobileIron Sentry was installed.
5. Enter "show FIPS".
6. Verify "FIPS 140 mode is enabled" is displayed.

If the MobileIron Sentry Server does not report that FIPS mode is "enabled", this is a finding.'
  desc 'fix', 'Configure the MobileIron Sentry server to use a FIPS 140-2 validated cryptographic module.

On the MobileIron Sentry console, do the following:
1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set when MobileIron Sentry was installed.
3. Enter "enable".
4. When prompted, enter the "enable secret" set when MobileIron Sentry was installed.
5. Enter "configure terminal".
6. Enter the following command to enable FIPS: FIPS
7. Enter the following command to proceed with the necessary reload: do reload 
8. Enter "Yes" at saved configuration modified prompt.
9. Enter "Yes" at proceed do reload.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54471r802328_chk'
  tag severity: 'medium'
  tag gid: 'V-251036'
  tag rid: 'SV-251036r802330_rule'
  tag stig_id: 'MOIS-AL-001340'
  tag gtitle: 'SRG-NET-000510-ALG-000025'
  tag fix_id: 'F-54425r802329_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
