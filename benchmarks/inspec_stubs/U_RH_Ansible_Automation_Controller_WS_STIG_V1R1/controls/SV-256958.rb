control 'SV-256958' do
  title 'The Automation Controller NGINX web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.'
  desc 'It is important that Automation Controller NGINX web server display a default hosted application web paged and not a directory listing when a requested web page cannot be found, because the web server will be vulnerable to intrusion. For this reason, access to directory listings must be disabled.

If a user or attacker have access to the website directory listing, they may have access to all the files in that folder. Additionally, they may be privy to specific details regarding the web server.'
  desc 'check', %q(For each Automation Controller NGINX web server, a system administrator must view to see whether autoindex is turned on or off (autoindex on/autoindex off):

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; 
grep -E 'autoindex\s+on' $NGINXCONF && echo "FAILED"
 
If "FAILED" is displayed, this is a finding.)
  desc 'fix', "As a System Administrator for each Automation Controller nginx web server host, remove any configuration that turns the autoindexing on:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\\n' | sed -ne '/conf-path/{s/.*conf-path=\\(.*\\)/\\1/;p}' ` ;
sed -Ei -e '/autoindex\\s+on/d;' $NGINXCONF

To apply these changes to the running service immediately, restart the NGINX service with the following command:

sudo systemctl restart nginx"
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60633r903555_chk'
  tag severity: 'medium'
  tag gid: 'V-256958'
  tag rid: 'SV-256958r903555_rule'
  tag stig_id: 'APWS-AT-000620'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-60575r902387_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
