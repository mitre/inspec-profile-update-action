control 'SV-256952' do
  title 'All Automation Controller NGINX web servers must be configured to use a specified IP address and port.'
  desc 'From a security perspective, it is important that all Automation Controller NGINX web servers are configured to use a specified IP address and port because “listening” on all IP addresses poses a vulnerability to the web server.

Not confining the web server to a specified IP address and port puts all web server content at risk of access by bad actors wanting to take advantage of those resources.'
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server host, verify the web server is configured to use a static IP address and port.

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; grep '^\s*listen\s*\*\|\s*listen\s*\[.*\]\|\s*listen\s*0\.0\.0\.0\|\s*listen\s*\[.*\]|^\s*listen\s\+.*:[^[:digit:]\s]\+.*' $NGINXCONF && echo FAILED

If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server host, identify the allowed and/or designated IP address(es) for the Automation Controller system.

Replace any wildcard or ranged IP address references in the NGINX configuration with IP addresses from the pool of allowed and/or designated address.

Reload the NGINX server configurations for all NGINX processes:

$ pkill -HUP nginx'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60627r903524_chk'
  tag severity: 'medium'
  tag gid: 'V-256952'
  tag rid: 'SV-256952r903524_rule'
  tag stig_id: 'APWS-AT-000370'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-60569r902369_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
