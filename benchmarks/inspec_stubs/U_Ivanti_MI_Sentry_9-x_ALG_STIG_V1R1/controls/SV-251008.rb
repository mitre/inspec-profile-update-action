control 'SV-251008' do
  title 'The Sentry must enforce approved authorizations for logical access to information and system resources by enabling identity-based, role-based, and/or attribute-based security policies. These controls are enabled in MobileIron UEM (MobileIron Core) and applied by the Sentry for conditional access enforcement.'
  desc 'Successful authentication through Sentry must not automatically give an entity access to resources behind Sentry. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.'
  desc 'check', 'Verify the MobileIron Sentry is configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and attribute-based security policies. The Sentry system configured for ActiveSync, AppTunnel, and/or as a Kerberos Proxy ensures only authenticated and authorized apps and managed devices have access to backend resources. Refer to the MobileIron Sentry 9.8.0 Guide for Core pages 20-21 for more information. 

1. Log in to the Core Admin Portal. 
2. Go to Service >> Sentry. 
3. Verify the Sentry is configured with one or all the of the applicable services (ActiveSync, AppTunnel, or Kerberos Proxy). If no services are applied, this is a finding.
4. If Sentry is being used as an ActiveSync Proxy or AppTunnel, verify an Identity Certificate is configured for the Device Authentication Configuration in the Sentry Configuration and that CRL is enabled. If not, this is a finding.

Refer to the MobileIron Sentry 9.8.0 Guide on how to configure the specific Sentry Services. ActiveSync: Standalone Sentry for ActiveSync Email Section, AppTunnel: Standalone Sentry for AppTunnel Section Kerberos Proxy: Standalone Sentry for KKDCP Section.

MobileIron UEM applies security, privacy, lockdown, and sync policies to registered devices. These policies ensure that devices can connect only if they comply to an organization’s security requirements. Standalone Sentry gets device posture and compliance information from MobileIron UEM, and allows access to Email via ActiveSync or backend systems based on the device posture. 

1. Log in to the Core Admin Portal. 
2. Go to Policies and Configurations >> Policies. 
3. Verify the appropriate Lockdown and Security Policies are applied to the devices accessing systems behind the Sentry. 

If no policies are applied, this is a finding.

By default, Sentry allows unregistered devices to access the ActiveSync server. Use this setting to change Sentry’s behavior to block unregistered devices from access if configuring Sentry for ActiveSync. 

1. Log in to the Core Admin Portal. 
2. Go to Services >> Sentry >> Preferences. 
3. Verify "Yes" for Auto Block Unregistered Devices is applied. 

If not applied, this is a finding.'
  desc 'fix', 'Configure the Sentry to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.

1. Log in to the Core Admin Portal.
2. Go to Services >> Sentry. 
3. Create one or all of the applicable Sentry Services: ActiveSync, AppTunnel, or Kerberos Proxy based on the Sentry use case. (Refer to the MobileIron Sentry Guide on how to configure the specific Sentry Services. ActiveSync: Page 43; AppTunnel: Page 64; Kerberos Proxy: Page 92.)
4. If Sentry is being used as an ActiveSync Proxy or AppTunnel, configure an Identity Certificate for the Device Authentication Configuration in the Sentry Configuration and enable the CRL checkbox.
5. Save the Sentry configuration.
 
MobileIron UEM applies security, privacy, lockdown, and sync policies to registered devices. These policies ensure that devices can connect only if they comply to an organization’s security requirements. Standalone Sentry gets device posture and compliance information from MobileIron UEM and allows access to email via ActiveSync or backend systems based on the device posture.

1. Log in to the Core Admin Portal.
2. Go to Policies and Configurations >> Policies.
3. Create or edit the Lockdown and Security Policies.
4. Ensure the policies are applied to devices accessing systems behind a Sentry if configuring Sentry for ActiveSync.

By default, Sentry allows unregistered devices to access the ActiveSync server. Use this setting to change Sentry’s behavior to block unregistered devices from access if configuring Sentry for ActiveSync.

1. Log in to the Core Admin Portal. 
2. Go to Services >> Sentry >> Preferences. 
3. Change the Auto Block Unregistered Devices setting to "Yes". 
4. Click "Save".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54443r802244_chk'
  tag severity: 'medium'
  tag gid: 'V-251008'
  tag rid: 'SV-251008r802246_rule'
  tag stig_id: 'MOIS-AL-000010'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-54397r802245_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
