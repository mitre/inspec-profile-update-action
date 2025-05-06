control 'SV-100871' do
  title 'The vAMI must use a site-defined, user management system to uniquely identify and authenticate users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature. To ensure support to the enterprise, the authentication must utilize an enterprise solution.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine the enterprise user management system being used to uniquely identify and authenticate users.

If the vAMI is not configured to use the enterprise user management system, this is a finding.'
  desc 'fix', 'Consult the appropriate VMware technical guide to implement the site-specific enterprise user management system.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90221'
  tag rid: 'SV-100871r1_rule'
  tag stig_id: 'VRAU-VA-000195'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-96963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
