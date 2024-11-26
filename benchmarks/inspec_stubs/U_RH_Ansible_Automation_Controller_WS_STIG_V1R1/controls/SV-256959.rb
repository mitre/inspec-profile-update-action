control 'SV-256959' do
  title 'Debugging and trace information, within Automation Controller NGINX web server, used to diagnose the web server must be disabled.'
  desc 'It is important that Automation Controller NGINX web server debugging and trace information used to diagnose the web server is disabled, because debugging information can yield information about the Automation Controller NGINX webserver, like web server type, version, patches installed, plugins, modules, the hosted app’s code type. Back ends used for storage could be revealed, as well. An attacker would not need to cause an error condition to gain this information because they could reside in logs and general messages.

If debugging/trace information is enabled, attackers could get the information from logs and general information, without drawing attention to themselves via an error message.'
  desc 'check', %q(For each Automation Controller NGINX web server, a system administrator must check to determine if any error or debug information is being logged or generated:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ;  cat $NGINXCONF  | grep '^\s*error_log' && echo FAILED

If "FAILED" is displayed, this is a finding.)
  desc 'fix', "For each Automation Controller NGINX web server, a system administrator must complete the following steps. 

Verify the NGINX configuration file in use:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\\n' | sed -ne '/conf-path/{s/.*conf-path=\\(.*\\)/\\1/;p}' ` ;  echo $NGINXCONF

Remove the error_log directive from the NGINX configuration file.

Cause NGINX to reload its configuration file:

pkill -HUP nginx"
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60634r902389_chk'
  tag severity: 'medium'
  tag gid: 'V-256959'
  tag rid: 'SV-256959r902391_rule'
  tag stig_id: 'APWS-AT-000640'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-60576r902390_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
