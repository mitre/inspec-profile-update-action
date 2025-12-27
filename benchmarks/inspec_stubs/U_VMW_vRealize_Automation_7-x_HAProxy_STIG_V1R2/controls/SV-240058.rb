control 'SV-240058' do
  title 'HAProxy must limit access to the statistics feature.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to be accessible on a production DoD system. 

HAProxy provide a statistics page, which will display web browser statistics from any web browser if HAProxy has not been configured to connect the server statistics to a UNIX socket.'
  desc 'check', "At the command prompt, execute the following command:

grep 'stats socket' /etc/haproxy/haproxy.cfg

If the command does not return the line below, this is a finding.

stats socket /var/run/haproxy.sock mode 600 level admin"
  desc 'fix', 'Uninstall or deactivate features, services, and processes not needed by the web server for operation.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43291r665341_chk'
  tag severity: 'medium'
  tag gid: 'V-240058'
  tag rid: 'SV-240058r879587_rule'
  tag stig_id: 'VRAU-HA-000130'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-43250r665342_fix'
  tag 'documentable'
  tag legacy: ['SV-99803', 'V-89153']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
