control 'SV-256951' do
  title 'All Automation Controller NGINX web servers must protect system resources and privileged operations from hosted applications.'
  desc 'Automation Controller NGINX web servers may host too many applications. Each application will need certain system resources and privileged operations to operate correctly. The Automation Controller NGINX web servers must be configured to contain and control the applications and protect the system resources and privileged operations from those not needed by the application for operation.

Not limiting the application will exacerbate the potential harm a compromised application could cause to a system.'
  desc 'check', 'As a system administrator for each Automation Controller NGINX web server host, check if SELinux is enabled in enforcing mode:

getenforce | grep Enforcing  >/dev/null || echo FAILED

If "FAILED" is displayed, this is a finding.'
  desc 'fix', 'As a system administrator for each Automation Controller NGINX web server host, place the server in SELinux enforcing mode:

setenforce 1'
  impact 0.3
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60626r902365_chk'
  tag severity: 'low'
  tag gid: 'V-256951'
  tag rid: 'SV-256951r902367_rule'
  tag stig_id: 'APWS-AT-000350'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-60568r902366_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
