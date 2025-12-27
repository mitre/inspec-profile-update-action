control 'SV-251012' do
  title 'If Sentry stores secret or private keys, it must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder."
  desc 'check', 'Verify the Sentry uses encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions. 

On the MobileIron Sentry CLI console, do the following:
1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set when MobileIron Sentry was installed.
3. Enter "enable".
4. When prompted, enter the "enable secret" set when MobileIron Sentry was installed.
5. Enter "show FIPS".
6. Verify "FIPS 140 mode is enabled" is displayed.

If the MobileIron Sentry Server does not report that FIPS mode is "enabled", this is a finding.'
  desc 'fix', 'Configure the MobileIron Sentry server to use a FIPS 140-2-validated cryptographic module.

On the MobileIron Sentry console, do the following:
1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set when MobileIron Sentry was installed.
3. Enter "enable".
4. When prompted, enter the "enable secret" set when MobileIron Sentry was installed.
5. Enter "configure terminal".
6. Enter the following command to enable FIPS: FIPS
7. Enter the following command to proceed with the necessary reload: do reload
8. Enter "Yes" at save configuration modified prompt.
9. Enter "Yes" at proceed do reload.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54447r802256_chk'
  tag severity: 'medium'
  tag gid: 'V-251012'
  tag rid: 'SV-251012r802258_rule'
  tag stig_id: 'MOIS-AL-000170'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-54401r802257_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
