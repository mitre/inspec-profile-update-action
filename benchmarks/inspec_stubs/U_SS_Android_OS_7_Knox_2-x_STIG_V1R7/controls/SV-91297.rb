control 'SV-91297' do
  title 'The Samsung Android 7 with Knox VPN client must be configured in one of the following configurations: 1. Disabled 2. Configured for container use only 3. Configured for per app use for the personal side'
  desc 'The device VPN must be configured to disable access from the personal space/container since it is considered an untrusted environment. Therefore, apps located in the personal container on the device should not have the ability to access a DoD network. In addition, Smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'Not Applicable for the COBO use case.

The VPN client on Samsung Android 7 with Knox must be configured in one of the following configurations:
1. Disabled
2. Configured for container use only
3. Configured for per app use for the personal side

This validation procedure covers the second of these options. This procedure is Not Applicable if option 1 or 3 was implemented at the site.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device has VPN protection for the Knox container only enabled.

This validation procedure is performed on the MDM Administration Console only. 

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Get All Container Packages In Vpn Profile" setting in the "Generic VPN" rule. 
2. Verify the value of the setting is the list of all the Container Packages.
3. Ask the MDM administrator to display the list of configured VPN profiles in the "VPN profiles" rule.
4. Verify the list includes the organization VPN profile.

If the MDM console "Get All Container Packages In Vpn Profile" does not list all the Container Packages or "VPN profiles" does not list the organization VPN profile, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox VPN client in one of the following configurations so that the device VPN is not available in the personal space:
1. Disabled
2. Configured for container use only
3. Configured for per app use for the personal side

This implementation guidance covers the second of these options.

On the MDM Administration Console, do the following:
1. Configure the organization VPN profile in the "Enterprise VPN profiles" rule.
2. Enable "Add All Container Packages To Vpn" in the "Generic VPN" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76601'
  tag rid: 'SV-91297r1_rule'
  tag stig_id: 'KNOX-07-017110'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-83295r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
