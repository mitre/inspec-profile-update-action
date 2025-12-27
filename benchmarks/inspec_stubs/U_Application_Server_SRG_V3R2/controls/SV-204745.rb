control 'SV-204745' do
  title 'The application server must use an enterprise user management system to uniquely identify and authenticate users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated.  This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.

To ensure support to the enterprise, the authentication must utilize an enterprise solution.'
  desc 'check', "Review application server documentation and configuration settings to determine if the application server is using an enterprise solution to authenticate organizational users and processes running on the users' behalf.

If an enterprise solution is not being used, this is a finding."
  desc 'fix', 'Configure the application server to use an enterprise user management system to uniquely identify and authenticate users and processes acting on behalf of organizational users.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4865r282882_chk'
  tag severity: 'medium'
  tag gid: 'V-204745'
  tag rid: 'SV-204745r508029_rule'
  tag stig_id: 'SRG-APP-000148-AS-000101'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-4865r282883_fix'
  tag 'documentable'
  tag legacy: ['V-35299', 'SV-46586']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
