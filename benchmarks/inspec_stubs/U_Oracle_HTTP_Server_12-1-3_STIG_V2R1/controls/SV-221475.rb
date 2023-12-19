control 'SV-221475' do
  title 'OHS must use FIPS modules to encrypt passwords during transmission.'
  desc 'Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the web server for many reasons. 

Examples include data passed from a user to the web server through an HTTPS connection for authentication, the web server authenticating to a backend database for data retrieval and posting, and the web server authenticating to a clustered web server manager for an update.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23190r415108_chk'
  tag severity: 'high'
  tag gid: 'V-221475'
  tag rid: 'SV-221475r415110_rule'
  tag stig_id: 'OH12-1X-000241'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-23179r415109_fix'
  tag 'documentable'
  tag legacy: ['SV-78899', 'V-64409']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
