control 'SV-256955' do
  title 'Cookies exchanged between any Automation Controller NGINX web server and any client, such as session cookies, must have security settings that disallow cookie access outside the originating Automation Controller NGINX web server and hosted application.'
  desc 'It is important that cookies exchanged between any Automation Controller NGINX webserver and any client have security settings that do not allow cookie access outside the originating Automation Controller server and the hosted application. This is because exchanged cookies may have session information such as user credentials that enable the web server application and the client to maintain a persistent connection.

If cookie access outside of the originating Automation Controller NGINX webserver and the hosted application are allowed, it puts the security of the server at risk of malicious acts by bad actors.

'
  desc 'check', "The Automation Controller application configures cookie properties appropriately by default. Any local modifications to cookie-related settings must be located and removed.

As a System Administrator for each Automation Controller NGINX web server host, search for modified cookie variables in the Automation Controller configuration:

sudo grep -r -E '(CSRF|SESSION)_COOKIE_(HTTPONLY|SECURE|SAMESITE)' /etc/tower/settings.py /etc/tower/conf.d/

If any output is shown, this is a finding."
  desc 'fix', "As a System Administrator for each Automation Controller NGINX web server host, remove any local variable changes related to cookie properties:

sudo grep -r -E '(CSRF|SESSION)_COOKIE_(HTTPONLY|SECURE|SAMESITE)' /etc/tower/settings.py /etc/tower/conf.d/

For each result, edit the relevant file. For example, if a variable is found in /etc/tower/settings.py, edit the file with the following command:

sudo -e /etc/tower.settings.py

Remove any line where the following variables are defined:

SESSION_COOKIE_HTTPONLY
SESSION_COOKIE_SECURE
SESSION_COOKIE_SAMESITE
CSRF_COOKIE_HTTPONLY
CSRF_COOKIE_SECURE
CSRF_COOKIE_SAMESITE

Execute the following command to restart the Automation Controller service:

sudo automation-controller-service restart"
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60630r902377_chk'
  tag severity: 'medium'
  tag gid: 'V-256955'
  tag rid: 'SV-256955r902379_rule'
  tag stig_id: 'APWS-AT-000480'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-60572r902378_fix'
  tag satisfies: ['SRG-APP-000223-WSR-000011', 'SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag 'documentable'
  tag cci: ['CCI-001664', 'CCI-002418']
  tag nist: ['SC-23 (3)', 'SC-8']
end
