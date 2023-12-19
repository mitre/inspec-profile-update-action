control 'SV-221483' do
  title 'OHS must have the SSLCARevocationFile and SSLCRLCheck directives within each SSL-enabled VirtualHost directive set to perform RFC 5280-compliant certification path validation when using single certification revocation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', '1. If using a single, certification revocation list file for revocation checks that is < 1 MB in size, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCARevocationFile" and "SSLCRLCheck" directives at the OHS server and virtual host configuration scopes.

3. If these directives are omitted or set improperly, this is a finding.'
  desc 'fix', '1. Place the certificate revocation list file within the wallet directory (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/keystores).

2. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

3. Search for the "SSLCARevocationFile" directive at the OHS server and virtual host configuration scopes.

4. Set the "SSLCARevocationFile" directive to the location (i.e., file within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the combined .crl file issued by the DoD CAs, add the directive if it does not exist.

5. Set the "SSLCRLCheck" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23198r415132_chk'
  tag severity: 'medium'
  tag gid: 'V-221483'
  tag rid: 'SV-221483r879612_rule'
  tag stig_id: 'OH12-1X-000249'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-23187r415133_fix'
  tag 'documentable'
  tag legacy: ['SV-78915', 'V-64425']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
