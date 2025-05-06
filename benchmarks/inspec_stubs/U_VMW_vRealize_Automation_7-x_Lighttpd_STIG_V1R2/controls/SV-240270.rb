control 'SV-240270' do
  title 'Lighttpd must be configured to use the SSL engine.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

In order to protect the integrity and confidentiality of the remote sessions, Lighttpd uses SSL/TLS.'
  desc 'check', %q(At the command prompt, execute the following command:

$ grep '^ssl.engine' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value returned for "ssl.engine" is not set to "enable", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf  

Configure the "lighttpd.conf" file with the following value: 

ssl.engine = "enable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43503r667985_chk'
  tag severity: 'medium'
  tag gid: 'V-240270'
  tag rid: 'SV-240270r879810_rule'
  tag stig_id: 'VRAU-LI-000465'
  tag gtitle: 'SRG-APP-000439-WSR-000152'
  tag fix_id: 'F-43462r667986_fix'
  tag 'documentable'
  tag legacy: ['SV-99965', 'V-89315']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
