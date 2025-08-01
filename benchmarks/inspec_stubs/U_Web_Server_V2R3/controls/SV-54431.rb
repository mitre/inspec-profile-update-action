control 'SV-54431' do
  title 'Warning and error messages displayed to clients must be modified to minimize the identity of the web server, patches, loaded modules, and directory paths.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether the web server offers different modes of operation that will minimize the identity of the web server, patches, loaded modules, and directory paths given to clients on error conditions.

If the web server is not configured to minimize the information given to clients, this is a finding.'
  desc 'fix', 'Configure the web server to minimize the information provided to the client in warning and error messages.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48242r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41854'
  tag rid: 'SV-54431r3_rule'
  tag stig_id: 'SRG-APP-000266-WSR-000159'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-47313r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
