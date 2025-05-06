control 'SV-214338' do
  title 'The Apache web server must restrict the ability of users to launch denial-of-service (DoS) attacks against other information systems or networks.'
  desc 'Apache web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation.

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "Timeout" directive is specified in the "httpd.conf" file to have a value of "10" seconds or less.

If the "Timeout" directive is not configured or set for more than "10" seconds, this is a finding.)
  desc 'fix', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Add or modify the "Timeout" directive in the Apache configuration to have a value of "10" seconds or less.

"Timeout 10"

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15550r277517_chk'
  tag severity: 'medium'
  tag gid: 'V-214338'
  tag rid: 'SV-214338r505936_rule'
  tag stig_id: 'AS24-W1-000590'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-15548r277518_fix'
  tag 'documentable'
  tag legacy: ['SV-102515', 'V-92427']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
