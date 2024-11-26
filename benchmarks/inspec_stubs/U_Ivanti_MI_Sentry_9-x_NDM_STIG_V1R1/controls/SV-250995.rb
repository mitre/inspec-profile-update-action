control 'SV-250995' do
  title 'MobileIron Sentry must use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Sentry utilizing encryption is required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'Verify the Sentry uses encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions. 

On the MobileIron Sentry CLI console, do the following:
1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set at MobileIron Sentry installation.
3. Enter "enable".
4. When prompted, enter the "enable secret" set at MobileIron Sentry installation.
5. Enter "show FIPS".
6. Verify "FIPS 140 mode is enabled" is displayed.

If the MobileIron Sentry Server does not report that FIPS mode is "enabled", this is a finding.'
  desc 'fix', 'Configure the MobileIron Sentry server to use a FIPS 140-2-validated cryptographic module.

On the MobileIron Sentry console, do the following:
1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set at MobileIron Sentry installation.
3. Enter "enable".
4. When prompted, enter the "enable secret" set at MobileIron Sentry installation.
5. Enter "configure terminal".
6. Enter the following command to enable FIPS: FIPS
7. Enter the following command to proceed with the necessary reload: do reload
8. Enter "Yes" at saved configuration modified prompt.
9. Enter "Yes" at proceed do reload.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54430r802205_chk'
  tag severity: 'high'
  tag gid: 'V-250995'
  tag rid: 'SV-250995r802207_rule'
  tag stig_id: 'MOIS-ND-000530'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-54384r802206_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
