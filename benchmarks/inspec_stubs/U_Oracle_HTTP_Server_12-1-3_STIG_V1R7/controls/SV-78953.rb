control 'SV-78953' do
  title 'OHS must have the ListenBacklog properly set to restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc 'A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation. 

An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ListenBacklog" directive at the OHS server configuration scope.

3. If the directive is omitted or set less than the value of the Maximum Syn Connection Backlog network parameter of the OS, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ListenBacklog" directive at the OHS server configuration scope.

3. Set the "ListenBacklog" directive to a value equal to the Maximum Syn Connection Backlog network parameter of the OS; add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65215r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64463'
  tag rid: 'SV-78953r1_rule'
  tag stig_id: 'OH12-1X-000287'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-70393r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
