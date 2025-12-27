control 'SV-256945' do
  title 'Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Automation Controller NGINX front-end web server.'
  desc 'In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development website.

The process of developing on a functional production website entails a degree of trial and error and repeated testing. This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals. The opportunity for a malicious user to obtain files that reveal business logic and login schemes is high in this situation. The existence of such immature content on a web server represents a significant security risk that is totally avoidable.

The Automation Controller NGINX front-end web server must enforce, either internally or through an external utility, the signing of modules before they are implemented into a production environment. By signing modules, the author guarantees that the module has been reviewed and tested before production implementation.'
  desc 'check', %q(The Automation Controller does not require any nginx dynamic expansion modules to function. Determine if any dynamic modules are specified in the nginx configuration.

As a system administrator for each Automation Controller NGINX web server host execute the following:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
NGINXMODPATH=`nginx -V 2>&1 | tr ' ' '\n' | grep modules-path | sed -ne '/modules-path/{s/.*modules-path=\(.*\\)/\1/;p}'`
NGINXMODINC=`grep include /etc/nginx/nginx.conf | grep modules | awk '{print $2}' | xargs dirname`
grep -q load_module ${NGINXCONF} && echo FAILED
[ `ls -1 $NGINXMODPATH | wc -l` == 0 ]  || echo FAILED
[ `ls -1 $NGINXMODINC | wc -l` == 0 ]  || echo FAILED

If "FAILED" is displayed, this is a finding.)
  desc 'fix', %q(As a system administrator for each Automation Controller NGINX web server host, execute the following:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' `
NGINXMODPATH=`nginx -V 2>&1 | tr ' ' '\n' | grep modules-path | sed -ne '/modules-path/{s/.*modules-path=\(.*\\)/\1/;p}'`
NGINXMODINC=`grep include /etc/nginx/nginx.conf | grep modules | awk '{print $2}' | xargs dirname`
sudo rm -f ${NGINXMODPATH}/*
sudo rm -f ${NGINXMODINC}/*
sudo -e ${NGINXCONF}

In the editor, remove any lines that contain "load_module".

Save the file and exit the text editor. Run the following command to apply the changes:

sudo systemctl restart nginx)
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60620r903521_chk'
  tag severity: 'medium'
  tag gid: 'V-256945'
  tag rid: 'SV-256945r903522_rule'
  tag stig_id: 'APWS-AT-000240'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-60562r903522_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
