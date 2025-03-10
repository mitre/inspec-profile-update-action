control 'SV-256953' do
  title "Only authenticated system administrators or the designated PKI Sponsor for an Automation Controller NGINX web server must have access to any Automation Controller NGINX web server's private key."
  desc "Each Automation Controller NGINX web server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the Automation Controller NGINX web server and clients.

By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the Automation Controller NGINX web server."
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server host, verify the location of the NGINX configuration:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
TOWER_KEY=`sed -n 's/^\s*ssl_certificate_key\s*\(.*\\);/\1/p' $NGINXCONF`
stat -c "%a %U %G" $TOWER_KEY| grep "600 root awx" || echo "FAILED" 

If "FAILED" is displayed, this is a finding.)
  desc 'fix', "As a System Administrator for each Automation Controller NGINX web server host, set the permissions:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\\n' | sed -ne '/conf-path/{s/.*conf-path=\\(.*\\)/\\1/;p}' `
TOWER_KEY=`sed -n 's/^\\s*ssl_certificate_key\\s*\\(.*\\);/\\1/p' $NGINXCONF`
sudo chown root:awx $TOWER_KEY
sudo chmod 600 $TOWER_KEY"
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60628r903525_chk'
  tag severity: 'medium'
  tag gid: 'V-256953'
  tag rid: 'SV-256953r903525_rule'
  tag stig_id: 'APWS-AT-000400'
  tag gtitle: 'SRG-APP-000176-WSR-000096'
  tag fix_id: 'F-60570r902372_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
