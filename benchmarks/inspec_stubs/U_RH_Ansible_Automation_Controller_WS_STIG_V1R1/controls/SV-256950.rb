control 'SV-256950' do
  title 'All Automation Controller NGINX web servers must have Web Distributed Authoring (WebDAV) disabled.'
  desc 'Automation Controller NGINX web servers can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', %q(As a system administrator, for each Automation Controller NGINX web server host, check the Automation Controller NGINX web server configuration for WebDAV modules:

disallowed_modules=(nginx-dav-ext-module headers-more-nginx-module) ; echo "${disallowed_modules[*]}" | tr ' ' '\n' >tempfile ; nginx -V 2>&1 | grep module | tr ' ' '\n' | grep module | grep -v modules-path | grep -Ff tempfile && echo "FAILED"; rm -f tempfile

If "FAILED" is displayed, this is a finding.

Check the Automation Controller NGINX web server configuration for WebDAV modules for disallowed WebDAV verbs, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ;
grep dev_(.*)methods $NGINXCONF | grep  'COPY|MOVE|MKCO|PROPFIND|PROPPATCH|LOCK|UNLOCK' && echo 'FAILED'

If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a system administrator, for each Automation Controller nginx web server host, remove all WebDAV modules from the NGINX configuration file (nominally /etc/nginx/nginx.conf).

Reload the NGINX server configurations for all NGINX processes:

$ pkill -HUP nginx'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60625r902362_chk'
  tag severity: 'medium'
  tag gid: 'V-256950'
  tag rid: 'SV-256950r902364_rule'
  tag stig_id: 'APWS-AT-000340'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-60567r902363_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
