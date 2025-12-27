control 'SV-240237' do
  title 'Lighttpd must prohibit unnecessary services, functions or processes.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome. Individual productivity tools have no legitimate place or use on an enterprise, production web server and they are also prone to their own security risks.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine if any unnecessary services, functions or processes are running on the web server. 

 If any unnecessary services, functions or processes are running on the web server, this is a finding.'
  desc 'fix', 'Remove or disable any unnecessary services, functions or processes.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43470r667886_chk'
  tag severity: 'medium'
  tag gid: 'V-240237'
  tag rid: 'SV-240237r879587_rule'
  tag stig_id: 'VRAU-LI-000160'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-43429r667887_fix'
  tag 'documentable'
  tag legacy: ['SV-99907', 'V-89257']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
