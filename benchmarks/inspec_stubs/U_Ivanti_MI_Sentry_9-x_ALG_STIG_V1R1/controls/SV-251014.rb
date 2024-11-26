control 'SV-251014' do
  title 'The Sentry providing intermediary services for remote access communications traffic must use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
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
  tag check_id: 'C-54449r802262_chk'
  tag severity: 'medium'
  tag gid: 'V-251014'
  tag rid: 'SV-251014r802264_rule'
  tag stig_id: 'MOIS-AL-000190'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-54403r802263_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
