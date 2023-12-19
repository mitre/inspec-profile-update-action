control 'SV-256942' do
  title 'The Automation Controller NGINX web server must use cryptography on all remote connections.'
  desc "Nondisplayed data on a web page may expose information that could put the organization at risk and negatively affect data integrity.

Automation Controller's web server must be configured such that all connections, regardless of their origin, between the server and the user are encrypted using cryptography."
  desc 'check', %q(As any user, execute the following command, substituting "<controller_fqdn>" for the hostname of the Automation Controller:

curl -s -w '%{redirect_url}\n' -o /dev/null http://<controller_fqdn>/api/v2/ping/  | grep '^https' >/dev/null || echo FAILED

If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a System Administrator, locate the inventory file used to install Ansible Automation Platform (usually in the installer directory). Edit this file and ensure the "nginx_disable_https" variable is absent or is set to "false".

Run the setup.sh command in the installer directory to reconfigure the controller to use the new setting:

sudo ./setup.sh'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60617r903519_chk'
  tag severity: 'medium'
  tag gid: 'V-256942'
  tag rid: 'SV-256942r903519_rule'
  tag stig_id: 'APWS-AT-000040'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-60559r902339_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
