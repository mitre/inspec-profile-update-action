control 'SV-240970' do
  title 'vIDM must be configured correctly for the site enterprise user management system.'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature. To ensure support to the enterprise, the authentication must utilize an enterprise solution.'
  desc 'check', "Interview the ISSO. Obtain the correct configuration for the site's Directory services.

In a browser, log in with Tenant admin privileges and navigate to the Administration page.

Select Directories Management >> Directories.

Click on the configured Directory to review the configuration. 

If the Directory service is not configured correctly, this is a finding."
  desc 'fix', "Interview the ISSO. Obtain the correct configuration for the site's Directory services.

In a browser, log in with Tenant admin privileges, and navigate to the Administration page.

Select Directories Management >> Directories.

Click on the configured Directory to edit the configuration in accordance with the instructions provided by the ISSO."
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vIDM'
  tag check_id: 'C-44203r676169_chk'
  tag severity: 'medium'
  tag gid: 'V-240970'
  tag rid: 'SV-240970r879589_rule'
  tag stig_id: 'VRAU-VI-000195'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-44162r676170_fix'
  tag 'documentable'
  tag legacy: ['SV-100935', 'V-90285']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
