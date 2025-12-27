control 'SV-256906' do
  title 'Automation Controller must be configured to authenticate users individually, prior to using a group authenticator.'
  desc 'Default superuser accounts, such as "root", are considered group authenticators. In the case of Automation Controller this is the "admin" account.'
  desc 'check', 'Log in to the Automation Controller web console as an administrator and navigate to Access >> Users.

The only local user allowed is the default/breakglass "admin". All other users need to come from an external authentication source. If any other local users exist, this is a finding.'
  desc 'fix', 'Log in to the Automation Controller web console as an administrator and navigate to Access >> Users.

Click the Username to be removed.

Select "Delete" and confirm.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60581r902286_chk'
  tag severity: 'medium'
  tag gid: 'V-256906'
  tag rid: 'SV-256906r902288_rule'
  tag stig_id: 'APAS-AT-000050'
  tag gtitle: 'SRG-APP-000153-AS-000104'
  tag fix_id: 'F-60523r902287_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
