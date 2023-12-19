control 'SV-256967' do
  title "All accounts installed with the Automation Controller NGINX web server's software and tools must have passwords assigned and default passwords changed."
  desc 'During installation of the Automation Controller NGINX web server software, accounts are created for the web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first thing an attacker will try when presented with a login screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the login even easier. Once the Automation Controller NGINX web server is installed, the passwords for any created accounts must be changed and documented. The new passwords must meet the requirements for all passwords (i.e., upper/lower characters, numbers, special characters, time until change, reuse policy, etc.).

Service accounts or system accounts that have no login capability do not need to have passwords set or changed.'
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server host, verify the NGINX account is configured to disallow interactive login"

grep '^nginx.*\(/sbin/nologin$\|/bin/false$\\)' /etc/passwd

If "FAILED" is displayed, this is a finding.)
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server host, change the NGINX account to disallow interactive login:

$ usermod -s /sbin/nologin nginx'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60642r903537_chk'
  tag severity: 'medium'
  tag gid: 'V-256967'
  tag rid: 'SV-256967r903537_rule'
  tag stig_id: 'APWS-AT-000950'
  tag gtitle: 'SRG-APP-000516-WSR-000079'
  tag fix_id: 'F-60584r902414_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
