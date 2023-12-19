control 'SV-100937' do
  title 'vIDM must utilize encryption when using LDAP for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. Application servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the application server utilizes LDAP, the LDAP traffic must be encrypted.'
  desc 'check', 'In a browser, log in with Tenant admin privileges, and navigate to the Administration page.

Select Directories Management >> Directories.

Click on the configured Directory to review the configuration. 

If the SSL checkbox is not selected, this is a finding.

Note: The checkbox is labeled, "This Directory requires all connections to use SSL".'
  desc 'fix', 'In a browser, log in with Tenant admin privileges, and navigate to the Administration page.

Select Directories Management >> Directories.

Click on the configured Directory to review the configuration. 

Check the checkbox that is labeled, "This Directory requires all connections to use SSL". 

Click "Save".'
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x vIDM'
  tag check_id: 'C-89979r1_chk'
  tag severity: 'high'
  tag gid: 'V-90287'
  tag rid: 'SV-100937r1_rule'
  tag stig_id: 'VRAU-VI-000240'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-97029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
