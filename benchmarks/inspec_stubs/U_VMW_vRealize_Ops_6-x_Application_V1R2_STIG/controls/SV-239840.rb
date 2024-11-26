control 'SV-239840' do
  title 'The vRealize Operations server must use an enterprise user management system to uniquely identify and authenticate users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated.  This is typically accomplished via the use of a user store that is either local (OS-based) or centralized (LDAP) in nature.

To ensure support to the enterprise, the authentication must utilize an enterprise solution.'
  desc 'check', 'Obtain the site configuration control policy from the ISSO.

Review site procedures to determine if an enterprise management system is used to uniquely identify and authenticate users.

If an enterprise management solution is not used, this is a finding.'
  desc 'fix', 'Configure vROps to use an enterprise user management system and document this in the site configuration control policy.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x Application'
  tag check_id: 'C-43073r664012_chk'
  tag severity: 'medium'
  tag gid: 'V-239840'
  tag rid: 'SV-239840r879589_rule'
  tag stig_id: 'VROM-AP-000195'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-43032r664013_fix'
  tag 'documentable'
  tag legacy: ['SV-98855', 'V-88205']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
