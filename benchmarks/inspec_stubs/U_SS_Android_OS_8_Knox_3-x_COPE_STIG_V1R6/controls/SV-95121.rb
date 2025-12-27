control 'SV-95121' do
  title 'The Samsung Android 8 with Knox VPN client must be configured in one of the following configurations:

1. Disabled;
2. Configured for CONTAINER use only; or
3. Configured for per app use for the personal side.'
  desc 'The device VPN must be configured to disable access from the personal space/CONTAINER since it is considered an untrusted environment. Therefore, apps located in the personal space on the device should not have the ability to access a DoD network. In addition, smartphones do not generally meet security requirements for computer devices to connect directly to DoD networks.

SFR ID: FMT_SMF_EXT.1.1 #3'
  desc 'check', 'The VPN client on Samsung Knox for Android must be configured in one of the following configurations:
1. Disabled;
2. Configured for CONTAINER use only; or
3. Configured for per app use for the personal side.

This validation procedure covers the second of these options. This procedure is Not Applicable (NA) if option 1 or 3 was implemented at the site.

Review Samsung Android 8 with Knox configuration settings to determine if the mobile device has VPN protection for the Knox CONTAINER only enabled.

This validation procedure is performed on the MDM Administration Console only. 

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Get All CONTAINER Packages In VPN Profile" setting in the "Generic VPN" rule. 
2. Verify the value of the setting is the list of all the CONTAINER packages.
3. Ask the MDM administrator to display the list of configured VPN profiles in the "VPN profiles" rule.
4. Verify the list includes the organization VPN profile.

If the MDM console "Get All CONTAINER Packages In VPN Profile" does not list all the CONTAINER Packages or "VPN profiles" does not list the organization VPN profile, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox VPN client in one of the following configurations so the device VPN is not available in the personal space:
1. Disabled;
2. Configured for CONTAINER use only; or
3. Configured for per app use for the personal side.

This implementation guidance covers the second of these options.

On the MDM Administration Console, do the following:
1. Configure the organization VPN profile in the "Enterprise VPN profiles" rule.
2. Enable "Add All CONTAINER Packages To VPN" in the "Generic VPN" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80089r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80417'
  tag rid: 'SV-95121r1_rule'
  tag stig_id: 'KNOX-08-023100'
  tag gtitle: 'PP-MDF-301060'
  tag fix_id: 'F-87223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
