control 'SV-256957' do
  title 'The Automation Controller NGINX web server must limit the character set used for data entry.'
  desc "It is important that Automation Controller NGINX web server limit the character set used for data entry and disallow Unicode use in hosted applications to avoid application compromise. Definition of the available character set for data entry can trap efforts to bypass security checks. The presence of nonstandard characters may cause the browser to interpret the content using a different character set than the defined one, because the system may interpret the content using a different CHARSET. Nonstandard encodings like UTF-7 can be used to bypass the application's defensive filters.

If character sets for data entry are not defined, it leaves open the door for attackers to bypass security checks and make the server vulnerable to malicious attack."
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server, verify the configuration requires a charset is mandatory.

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; grep 'charset_required' $NGINXCONF || echo "FAILED"

If "FAILED" is displayed, this is a finding.)
  desc 'fix', "As a System Administrator for each Automation Controller NGINX web server, verify the NGINX web server configuration file in use is located at '/etc/nginx/nginx.conf'

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\\n' | sed -ne '/conf-path/{s/.*conf-path=\\(.*\\)/\\1/;p}' ` ; 

Add the directive to the NGINX configuration to force a required charset.

sed -i  '/location/i charset_required; ' $NGINXCONF

Reload the NGINX server configurations for all NGINX processes.

$ pkill -HUP nginx"
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60632r902383_chk'
  tag severity: 'medium'
  tag gid: 'V-256957'
  tag rid: 'SV-256957r903552_rule'
  tag stig_id: 'APWS-AT-000610'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-60574r902384_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
