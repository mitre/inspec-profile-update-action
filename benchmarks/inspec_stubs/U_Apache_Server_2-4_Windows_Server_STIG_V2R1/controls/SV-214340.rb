control 'SV-214340' do
  title 'Debugging and trace information used to diagnose the Apache web server must be disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

For any enabled "TraceEnable" directives, verify they are part of the server=level configuration (i.e., not nested in a "Directory" or "Location" directive).

Also verify the "TraceEnable" directive is set to "Off".

If the "TraceEnable directive is not part of the server-level configuration and/or is not set to "Off", this is a finding.

If the directive does not exist in the conf file, this is a finding because the default value is "On".)
  desc 'fix', %q(Edit the <'INSTALL PATH'>\conf\httpd.conf file and add or set the value of "TraceEnable" to "Off".

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15552r277523_chk'
  tag severity: 'medium'
  tag gid: 'V-214340'
  tag rid: 'SV-214340r505936_rule'
  tag stig_id: 'AS24-W1-000630'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-15550r277524_fix'
  tag 'documentable'
  tag legacy: ['V-92431', 'SV-102519']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
