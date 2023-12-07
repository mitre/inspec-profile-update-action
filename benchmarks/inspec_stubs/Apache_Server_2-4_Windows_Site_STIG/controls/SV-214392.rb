control 'SV-214392' do
  title 'The Apache web server must be tuned to handle the operational requirements of the hosted application.'
  desc 'A denial of service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.

'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file. 

Verify the "Timeout" directive is specified to have a value of "10" seconds or less.

If the "Timeout" directive is not configured or is set for more than "10" seconds, this is a finding.)
  desc 'fix', 'Add or modify the "Timeout" directive in the Apache configuration to have a value of "10" seconds or less.

"Timeout 10"'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15603r277917_chk'
  tag severity: 'medium'
  tag gid: 'V-214392'
  tag rid: 'SV-214392r400402_rule'
  tag stig_id: 'AS24-W2-000830'
  tag gtitle: 'SRG-APP-000435-WSR-000148'
  tag fix_id: 'F-15601r277918_fix'
  tag satisfies: ['SRG-APP-000435-WSR-000148', 'SRG-APP-000246-WSR-000149']
  tag 'documentable'
  tag legacy: ['SV-102667', 'V-92579']
  tag cci: ['CCI-001094', 'CCI-002385']
  tag nist: ['SC-5 (1)', 'SC-5 a']
end
