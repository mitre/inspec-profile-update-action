control 'SV-256965' do
  title 'The Automation Controller NGINX web servers must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications.

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server host, verify the NGINX web server configuration file in use is located at "/etc/nginx.nginx.conf":

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` 

If the file does not exist, this is a finding.

Verify the use of only dynamic modules witch are allowed by organizational policy:

allowed_modules=(ssl_module http_v2_module http_realip_module http_addition_module http_xslt_module=dynamic http_image_filter_module=dynamic http_sub_module http_dav_module  http_mp4_module http_gunzip_module http_gzip_static_module http_random_index_module http_secure_link_module http_degradation_module http_slice_module http_stub_status_module http_perl_module=dynamic http_auth_request_module mail_ssl_module stream_ssl_preread_module http_flv_module) ; echo "${allowed_modules[*]}" | tr ' ' '\n' >/tmp/allowed_modules ; nginx -V 2>&1 | grep module | tr ' ' '\n' | grep module | grep -v modules-path | grep -v -Ff /tmp/allowed_modules && echo "FAILED";

Verify the use of only runtime modules which are allowed by organizational policy:

grep load_module $NGINXCONF  | sed -n 's/^\s*load_module\s*\(.*\\)/\1/p' | grep -v -Ff /tmp/allowed_modules && echo "FAILED" ; rm -f /tmp/allowed_modules

If the output shows "FAILED", this is a finding.)
  desc 'fix', %q(As a System Administrator for each Automation Controller NGINX web server host, verify the NGINX web server configuration file in use is located at "/etc/nginx.nginx.conf":

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; 

Verify the location of the NGINX modules libraries:

pushd `nginx -V 2>&1 | grep module | tr ' ' '\n' | grep module | sed -n 's/.*modules-path.*=\s*\(.*\\)/\1/p'`

Remove all modules that violate organizationally defined policy.
Examine runtime loaded modules:

grep load_module nginx.conf.test | sed -n 's/^\s*load_module\s*\(.*\\)/\1/p'

Remove all modules that violate organizationally defined policy.
Examine the remainder of the modules:

nginx -V 2>&1 | grep module | tr ' ' '\n' | grep module | grep -v modules-path 

These modules are compiled into the core NGINX binaries are cannot be removed. Use of any these modules that violate organizationally defined policy must be mitigated.

To apply these changes to the running service immediately, restart the NGINX service with the following command:

sudo systemctl restart nginx

Alternatively, reinstall Automation Controller for each web server host.)
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60640r902407_chk'
  tag severity: 'medium'
  tag gid: 'V-256965'
  tag rid: 'SV-256965r902409_rule'
  tag stig_id: 'APWS-AT-000920'
  tag gtitle: 'SRG-APP-000441-WSR-000181'
  tag fix_id: 'F-60582r902408_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
