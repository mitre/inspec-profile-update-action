control 'SV-256954' do
  title 'All Automation Controller NGINX web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.'
  desc "AIT is important to limit access to Automation Controller nginx web servers and provide access on a need-to-know basis. For example, only System Administrators must have access to all the system's capabilities, while the web administrator and associated staff require access and control of the web content and Automation Controller NGINX web server configuration files.

Without close monitoring and control over access to the web server and its resources, there is the risk of unskilled personnel making mistakes, and a risk of characters performing malicious acts."
  desc 'check', %q(As a system administrator for each Automation Controller NGINX web server host, enumerate all (nonroot) privileged users on the system:

allowed_privileged_users=('root') ; echo "${allowed_privileged_users}" | tr ' ' '\n' >/tmp/allowed_privileged_users ; getent passwd | cut -f1 -d ':' | sudo xargs -L1 sudo -l -U | grep -v 'not allowed' | tail -n +3 | sed -n '/^User/s/User\s*\(\w*\\).*/\1/p' | grep -v -f /tmp/allowed_privileged_users 1>/dev/null && echo "FAILED" ; rm -f /tmp/allowed_privileged_users

If "FAILED" is displayed, this is a finding.)
  desc 'fix', "As a System Administrator for each Automation Controller NGINX web server host, enumerate all (nonroot) privileged users on the system:

getent passwd | cut -f1 -d ':' | sudo xargs -L1 sudo -l -U | grep -v 'not allowed' | tail -n +3 | sed -n '/^User/s/User\\s*\\(\\w*\\).*/\\1/p' | grep -v root

For each user shown, perform one of the following actions:
- Remove the indicated user from the system;
- Remove the indicated user from any privileged groups (wheel);
- Remove login access for the user;
- Verify via organizationally defined procedures the indicated user is an authorized administrative account."
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60629r903528_chk'
  tag severity: 'medium'
  tag gid: 'V-256954'
  tag rid: 'SV-256954r903528_rule'
  tag stig_id: 'APWS-AT-000440'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-60571r902375_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
