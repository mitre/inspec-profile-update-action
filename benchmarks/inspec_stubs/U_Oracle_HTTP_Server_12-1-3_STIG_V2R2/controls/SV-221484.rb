control 'SV-221484' do
  title 'OHS must have SSLCARevocationPath and SSLCRLCheck directives within each SSL-enabled VirtualHost directive set to perform RFC 5280-compliant certification path validation when using multiple certification revocation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', '1. If using multiple certificate revocation list files for revocation checks, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCARevocationPath" and "SSLCRLCheck" directives at the OHS server and virtual host configuration scopes.

3. If these directives are omitted or set improperly, this is a finding.'
  desc 'fix', '1. Place the certificate revocation list files within the wallet directory (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores).

2. After confirming that the Certificate Authorities that signed the certificate revocation list files are in the Oracle wallet, create the hash symbolic link files for each of the certificate revocation list files (e.g., $ORACLE_HOME/oracle_common/bin/orapki crl hash -crl $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores/wallet/<my_base64.crl> -symlink $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores/wallet -wallet $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores/wallet).

3. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

4. Search for the "SSLCARevocationPath" directive at the OHS server and virtual host configuration scopes.

5. Set the "SSLCARevocationPath" directive to the path (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) that contains the hash symbolic links that point to the certificate revocation list files issued by the DoD CAs that are in Base64 format; add the directive if it does not exist.

6. Set the "SSLCRLCheck" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23199r415135_chk'
  tag severity: 'medium'
  tag gid: 'V-221484'
  tag rid: 'SV-221484r879612_rule'
  tag stig_id: 'OH12-1X-000250'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-23188r415136_fix'
  tag 'documentable'
  tag legacy: ['SV-78917', 'V-64427']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
