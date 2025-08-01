control 'SV-256964' do
  title 'Automation Controller NGINX web servers must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.'
  desc 'check', %q(As a System Administrator, for each Automation Controller NGINX web server, a TLS Configuration Check validates the TLS version used by the server:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
sudo grep ssl_protocols ${NGINXCONF} | grep -E 'ssl_protocols\s+TLSv1.2;' || echo "FAILED"

If "FAILED" is displayed, this is a finding.)
  desc 'fix', %q(As a System Administrator for each Automation Controller Web Server, reconfigure the TLS versions or ciphers used in Automation Controller's web server:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
sudo -e ${NGINXCONF}

Replace the line beginning with "ssl_protocols" to match (note the leading spaces):
"        ssl_protocols TLSv1.2;"

If the "ssl_protocols" variable does not exist, add it after the line beginning with "ssl_ciphers".

Save the file and exit the text editor. To apply these changes to the running service immediately, restart the NGINX service with the following command:

sudo systemctl restart nginx)
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60639r902404_chk'
  tag severity: 'medium'
  tag gid: 'V-256964'
  tag rid: 'SV-256964r903551_rule'
  tag stig_id: 'APWS-AT-000900'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-60581r902405_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
