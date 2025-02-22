control 'SV-91199' do
  title 'The Akamai Luna Portal must employ Single Sign On (SSO) with Security Assertion Markup Language (SAML) integration to verify authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', %q(Verify that the Luna portal is configured to use single sign-on (SSO) with SAML.

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click "Configure" >> "Manage SSO with SAML"
3. Verify the identity Provider's current SSO settings are configured properly.

If SSO with SAML is not configured, then this is a finding.)
  desc 'fix', %q(Configure the Luna portal to use single sign-on with SAML.

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click "Configure" >> "Manage SSO with SAML"
3. Configure the identity Provider's SSO settings as follows:
  a. The strings in some fields—such as the local user attribute name (“userid”) and the last part of the service provider endpoint address (“.luna-sp.com”)—are pre-specified by Luna  Control Center. Using the information about your identity provider (IDP). Fill in the first three fields:
   - Service Provider End-point
   - Entity ID
   - Single Sign-On URL
  b. The next field, "Single Logout URL", is optional. If your SAML metadata includes this information and you wish to configure for a Single Logout, you may enter it here.
  c. Enter an email address that should receive notifications from Luna Control Center.
  d. Enter thex509c Certificate key.
  e. The next field, Alternate x509c Certificate Key, is optional. If you have an alternate x509c Certificate key, you may enter it here. Having a second key can be convenient if your current key is nearing expiration and your IDP supports key rotation.
  f. When the required information has been entered, click "Save" or click "Save & Activate".
   - Click Save if you want to keep a draft of your configuration without activating it yet. In the Manage Single Sign-On with SAML application’s main panel, “Inactive” then appears in the Status column of the new configuration. This means it has been saved but is not yet activated.
   - You may repeat all steps to this point, to create as many additional inactive SSO configurations as desired. They’ll all be listed and accessible from the main panel. (A filter is provided for convenience when dealing with long lists.)
   - When you want to activate one of your saved but inactive configurations, simply select "Activate" from its gear icon. This action results in a progression of status messages—which may take up to 48 hours—starting with "Pending activation" then "Pending activation (DNS)" and finally "Active."
   - Click "Save & Activate" if you want to immediately request activation of the new configuration. In the "Manage Single Sign-On with SAML" application’s main panel, "Pending activation" then appears in the "Status" column of the new configuration, indicating that it has been saved and is awaiting activation.
   - This action results in a progression of status messages, starting with "Pending activation (DNS)" and ending with "Active."
   - You may repeat all steps to this point, to create as many additional active configurations as desired.)
  impact 0.7
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76163r1_chk'
  tag severity: 'high'
  tag gid: 'V-76503'
  tag rid: 'SV-91199r1_rule'
  tag stig_id: 'AKSD-DM-000118'
  tag gtitle: 'SRG-APP-000516-NDM-000338'
  tag fix_id: 'F-83181r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
