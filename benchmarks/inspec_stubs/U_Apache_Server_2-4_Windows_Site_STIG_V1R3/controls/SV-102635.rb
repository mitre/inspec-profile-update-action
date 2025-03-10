control 'SV-102635' do
  title 'The Apache web server must be configured to provide clustering.'
  desc 'The web server may host applications that display information that cannot be disrupted, such as information that is time critical or life threatening. In these cases, a web server that shuts down or ceases to be accessible when there is a failure is not acceptable. In these types of cases, clustering of web servers is used.

Clustering of multiple web servers is a common approach to providing fail-safe application availability. To ensure application availability, the web server must provide clustering or some form of failover functionality.

'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "mod_proxy" is loaded.

If it does not exist, this is a finding.

If the "mod_proxy" module is loaded and the "ProxyPass" directive is not configured, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and load the "mod_proxy" module. 

Set the "ProxyPass" directive.)
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92547'
  tag rid: 'SV-102635r1_rule'
  tag stig_id: 'AS24-W2-000560'
  tag gtitle: 'SRG-APP-000225-WSR-000141'
  tag fix_id: 'F-98789r1_fix'
  tag satisfies: ['SRG-APP-000225-WSR-000141', 'SRG-APP-000356-WSR-000007']
  tag 'documentable'
  tag cci: ['CCI-001190', 'CCI-001844']
  tag nist: ['SC-24', 'AU-3 (2)']
end
