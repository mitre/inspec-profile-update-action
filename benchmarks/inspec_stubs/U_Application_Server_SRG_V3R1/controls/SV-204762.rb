control 'SV-204762' do
  title 'The application server must be configured to mutually authenticate connecting proxies, application servers or gateways.'
  desc 'Application architecture may sometimes require a configuration where an application server is placed behind a web proxy, an application gateway or communicates directly with another application server. In those instances, the application server hosting the service/application is considered the server. The application server, proxy or application gateway consuming the hosted service is considered a client. Authentication is accomplished via the use of certificates and protocols such as TLS mutual authentication. Authentication must be performed when the proxy is exposed to an untrusted network or when data protection requirements specified in the system security plan mandate the need to establish the identity of the connecting application server, proxy or application gateway.'
  desc 'check', 'Review application server documentation, system security plan and application data protection requirements. 

If the connected web proxy is exposed to an untrusted network or if data protection requirements specified in the system security plan mandate the need to establish the identity of the connecting application server, proxy or application gateway and the application server is not configured to mutually authenticate the application server, proxy server or gateway, this is a finding.'
  desc 'fix', 'Configure the application server to mutually authenticate proxy servers, other application servers and application gateways as specified.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4882r282933_chk'
  tag severity: 'medium'
  tag gid: 'V-204762'
  tag rid: 'SV-204762r508029_rule'
  tag stig_id: 'SRG-APP-000219-AS-000147'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-4882r282934_fix'
  tag 'documentable'
  tag legacy: ['SV-46668', 'V-35381']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
