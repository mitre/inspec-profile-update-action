control 'SV-214385' do
  title 'Debugging and trace information used to diagnose the Apache web server must be disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the Apache web server, an attacker does not need to cause an error condition to gain this information.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

For any enabled "TraceEnable" directives, verify they are part of the server-level configuration (i.e., not nested in a "Directory" or "Location" directive).

Also, verify the "TraceEnable" directive is set to "Off".

If the "TraceEnable" directive is not part of the server-level configuration and/or is not set to "Off", this is a finding.

If the directive does not exist in the "conf" file, this is a finding because the default value is "On".)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and add or set the value of "EnableTrace" to "Off".)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15596r277896_chk'
  tag severity: 'medium'
  tag gid: 'V-214385'
  tag rid: 'SV-214385r397843_rule'
  tag stig_id: 'AS24-W2-000630'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-15594r277897_fix'
  tag 'documentable'
  tag legacy: ['SV-102645', 'V-92557']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
