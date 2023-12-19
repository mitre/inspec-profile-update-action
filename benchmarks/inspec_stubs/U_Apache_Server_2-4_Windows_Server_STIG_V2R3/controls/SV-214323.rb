control 'SV-214323' do
  title 'The Apache web server must have resource mappings set to disable the serving of certain file types.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc.

The web server must only allow hosted application file types to be served to a user, and all other types must be disabled.

'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding.)
  desc 'fix', 'Disable MIME types for .exe, .dll, .com, .bat, and .csh programs.

If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, remove those references.

Restart the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15535r277472_chk'
  tag severity: 'medium'
  tag gid: 'V-214323'
  tag rid: 'SV-214323r879587_rule'
  tag stig_id: 'AS24-W1-000300'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-15533r277473_fix'
  tag satisfies: ['SRG-APP-000141-WSR-000081', 'SRG-APP-000141-WSR-000083']
  tag 'documentable'
  tag legacy: ['SV-102469', 'V-92381']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
