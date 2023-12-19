control 'SV-256946' do
  title 'All Automation Controller NGINX front-end web servers must not perform user management for hosted applications.'
  desc "Web servers require enterprise-wide user management capability in order to prevent unauthorized access, with features like attempt lockouts and password complexity requirements.

Unauthorized access to the web server makes the web server and the organization vulnerable to attack.

Note: The underlying NGINX web server does not perform user management or authentication. The Automation Controller includes user management and authentication capabilities. However, the user management controls built into Automation Controller may not be sufficient to enforce the appropriate level of password, sessions, and other policies required. It is strongly recommended that Automation Controller be configured to use the organization's Identity Management/Authentication Service. This may be an AD/LDAP service, OIDC, or other supported authentication service."
  desc 'check', 'As a system administrator for each Automation Controller NGINX web server host, navigate to Settings >> Authentication.

Review the configuration and verify that the appropriate authentication service is configured.

If no authentication service is configured, this is a finding.'
  desc 'fix', 'As a system administrator for each Automation Controller NGINX web server host, navigate to Settings >> Authentication.

Configure the appropriate authentication service.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60621r902350_chk'
  tag severity: 'medium'
  tag gid: 'V-256946'
  tag rid: 'SV-256946r902352_rule'
  tag stig_id: 'APWS-AT-000250'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-60563r902351_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
