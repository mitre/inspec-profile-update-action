control 'SV-214384' do
  title 'Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used.

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If the "ErrorDocument" directive is not being used, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and use the "ErrorDocument" directive to enable custom error pages.

ErrorDocument 500 "Sorry, our script crashed. Oh dear"
ErrorDocument 500 /cgi-bin/crash-recover
ErrorDocument 500 http://error.example.com/server_error.html
ErrorDocument 404 /errors/not_found.html
ErrorDocument 401 /subscription/how_to_subscribe.html

The syntax of the ErrorDocument directive is:

ErrorDocument <3-digit-code> <action>

Additional Information:

https://httpd.apache.org/docs/2.4/custom-error.html)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15595r505104_chk'
  tag severity: 'medium'
  tag gid: 'V-214384'
  tag rid: 'SV-214384r505106_rule'
  tag stig_id: 'AS24-W2-000620'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-15593r505105_fix'
  tag 'documentable'
  tag legacy: ['SV-102643', 'V-92555']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
