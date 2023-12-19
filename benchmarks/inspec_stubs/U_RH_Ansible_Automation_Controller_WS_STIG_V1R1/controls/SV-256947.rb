control 'SV-256947' do
  title 'All Automation Controller NGINX web servers must not be a proxy server for any process other than the Automation Controller application.'
  desc 'The Automation Controller NGINX web server must be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common anonymous attack.

In a scenario where Automation Controller is still reachable without use of the proxy/load balancer or when the proxy does not validate the header, X-Forwarded-For can be spoofed fairly easily to fake the originating IP addresses. Using HTTP_X_FORWARDED_FOR in the REMOTE_HOST_HEADERS setting poses a vulnerability that essentially gives users access to certain resources that they must not have.

'
  desc 'check', %q(As a system administrator for each Automation Controller NGINX web server host, ensure that the only upstream servers configured are for the Automation Controller ASGI and WSGI modules:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
sudo grep -E 'proxy_pass|uwsgi_pass' $NGINXCONF | grep -Pqz '^\s+proxy_pass http://daphne;\n\s+uwsgi_pass uwsgi;\n$' || echo FAILED
[ "`sudo grep -Pzo 'upstream\s+daphne\s+{[^}]+}' $NGINXCONF | grep -a server | grep -v 'server unix:/var/run/tower/daphne.sock;'`" == '' ] || echo FAILED
[ "`sudo grep -Pzo 'upstream\s+uwsgi\s+{[^}]+}' $NGINXCONF | grep -a server | grep -v 'server unix:/var/run/tower/uwsgi.sock;'`" == '' ] || echo FAILED

If "FAILED" is displayed, this is a finding.

Ensure all locations are served by either these upstream servers or other well-known content:

[ "`sudo grep location $NGINXCONF | grep -v '^\s*#' | grep -Ev '^\s+location\s+/(favicon.ico|static|websocket)?\s+{'`" == "" ] || echo "FAILED"
sudo grep -Eq 'location\s+/favicon.ico\s+{\s+alias\s+/var/lib/awx/public/static/media/favicon.ico;\s+}' $NGINXCONF || echo "FAILED"
sudo grep -Eq 'location\s+/static\s+{\s+alias\s+/var/lib/awx/public/static;\s+}' $NGINXCONF || echo "FAILED"
sudo grep -Pzo 'location\s+/websocket\s+({([^{}]|(?1))*})' $NGINXCONF | grep -Eq '^\s+proxy_pass\s+http://daphne;' || echo "FAILED"
sudo grep -Pzo 'location\s+/\s+({([^{}]|(?1))*})' $NGINXCONF | grep -Eq '^\s+uwsgi_pass\s+uwsgi;' || echo "FAILED"

If "FAILED" is displayed, this is a finding.

Verify the content present and served from the static content location (/var/lib/awx/public/static) is acceptable per organizationally defined policy.

If any content present in this location (or its subdirectories) is not acceptable per organizationally defined policy, this is a finding.)
  desc 'fix', 'As a System Administrator, remove any content present and served from the static content location (/var/lib/awx/public/static) that is not acceptable per organizationally defined policy.

Run the setup.sh command in the Ansible Automation Platform installer directory to reconfigure the controller to the default state, which only contains the required configuration:

sudo ./setup.sh'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60622r903554_chk'
  tag severity: 'medium'
  tag gid: 'V-256947'
  tag rid: 'SV-256947r903554_rule'
  tag stig_id: 'APWS-AT-000270'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-60564r902354_fix'
  tag satisfies: ['SRG-APP-000141-WSR-000076', 'SRG-APP-000141-WSR-000083', 'SRG-APP-000141-WSR-000087']
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
