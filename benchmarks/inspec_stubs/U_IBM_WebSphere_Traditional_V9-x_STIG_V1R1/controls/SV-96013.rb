control 'SV-96013' do
  title 'The WebSphere Application Server LDAP user registry must be used.'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.

To ensure support to the enterprise, the authentication must utilize an enterprise solution.'
  desc 'check', 'In the administrative console, click Security >> Global security.

If the "Available realm definitions" drop down box under the "User account repository" section is not set to "Standalone LDAP registry", this is a finding.'
  desc 'fix', 'In the administrative console, click Security >> Global security.

Under "User account repository", click the "Available realm definitions" drop-down list.

Select "Standalone LDAP" registry.

Click "Configure".

Provide the Primary Administrative user name, type of LDAP server, hostname for the LDAP server, define the Base distinguished name.

Click "OK".

On "Global security" panel, click "Set as current".

Click "Apply".

Click "Save".

Recycle and synchronize the JVMS.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80997r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81299'
  tag rid: 'SV-96013r1_rule'
  tag stig_id: 'WBSP-AS-001010'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-88079r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
