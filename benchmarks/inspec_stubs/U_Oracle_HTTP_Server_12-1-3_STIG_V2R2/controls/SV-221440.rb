control 'SV-221440' do
  title 'OHS must have the SSLSessionCacheTimeout directive set properly.'
  desc 'During an SSL session, information about the session is stored in the global/inter-process SSL Session Cache, the OpenSSL internal memory cache and for sessions resumed by TLS session resumption (RFC 5077).  This information must not be allowed to live forever, but expire and become invalid so that an attacker cannot hijack the session if not closed by the hosted application properly.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLSessionCacheTimeout" directive at the OHS server configuration scope.

3. If the directive is omitted or is set greater than 60, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLSessionCacheTimeout" directive at the OHS server configuration scope.

3. Set the "SSLSessionCacheTimeout" directive to "60", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23155r415003_chk'
  tag severity: 'medium'
  tag gid: 'V-221440'
  tag rid: 'SV-221440r879887_rule'
  tag stig_id: 'OH12-1X-000202'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23144r415004_fix'
  tag 'documentable'
  tag legacy: ['SV-79133', 'V-64643']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
