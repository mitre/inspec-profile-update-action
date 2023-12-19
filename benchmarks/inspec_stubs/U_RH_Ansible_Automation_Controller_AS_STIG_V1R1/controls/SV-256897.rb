control 'SV-256897' do
  title 'Automation Controller must use encryption strength in accordance with the categorization of the management data during remote access management sessions.'
  desc 'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the application server via a network for the purposes of managing Automation Controller. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised.

Automation Controller is accessed via standard HTTP (redirect)/HTTPS on standard ports, provided by NGINX. A self-signed certificate/key is installed by default; however, a user can provide a locally appropriate certificate and key per their organizational policy. SSL/TLS algorithm support is configured in the /etc./nginx/nginx.conf configuration file.

'
  desc 'check', 'As an unauthenticated user, open a new web browser and go to http://<Automation Controller HOST>

If not redirected to https://<Automation Controller HOST>, this is a finding.'
  desc 'fix', 'Enable HTTPS by running the following command:

./setup.sh -e nginx_disable_https=false

The "nginx_disable_https" variable disables HTTPS traffic through NGINX, this is useful if offloading HTTPS to a load balancer.

By default, this variable is set to false in the installers "roles/nginx/defaults/main.yml" file. If a load balancer is not needed, ensure this value has not been set to true.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60572r903510_chk'
  tag severity: 'medium'
  tag gid: 'V-256897'
  tag rid: 'SV-256897r903510_rule'
  tag stig_id: 'APAS-AT-000011'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-60514r902260_fix'
  tag satisfies: ['SRG-APP-000014-AS-000009', 'SRG-APP-000142-AS-000014', 'SRG-APP-000172-AS-000120', 'SRG-APP-000441-AS-000258', 'SRG-APP-000442-AS-000259']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000382', 'CCI-002420', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'CM-7 b', 'SC-8 (2)', 'SC-8 (2)']
end
