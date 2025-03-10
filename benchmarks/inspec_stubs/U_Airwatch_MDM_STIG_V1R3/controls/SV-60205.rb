control 'SV-60205' do
  title 'The AirWatch MDM Server must provide the administrative functionality to specify a list of approved applications that must be installed on the mobile device and cannot be removed by the user.'
  desc 'DoD can perform due diligence on sources of software to mitigate the risk that malicious software is introduced to those sources.  Therefore, if software is downloaded from a DoD-approved source, then it is less likely to be malicious than if it is downloaded from an unapproved source.  To prevent access to unapproved sources, the operating system in most cases can be configured to disable user access to public application stores.  In some cases, some applications are required for secure operation of the mobile devices controlled by the AirWatch MDM Server.  In these cases, the ability for users to remove the application is needed as to ensure proper secure operations of the device.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure there is administrative functionality to specify a list of approved applications that must be installed on the mobile device and cannot be removed by the user. If this function is not present, this is a finding.

To verify Required Applications list on specific Android device Profile: (1) click "Menu" from top tool bar, (2) click "Profiles" under "Profiles and Policies" heading, (3) click on applicable Profile, and on left-hand toolbar (4) select "Application Control". (5) Ensure box "Prevent Removal of Required Apps" is checked.

Samsung Knox MOS:
To verify access to public store on Samsung SAFE devices is blocked: (1) click "Menu" from top tool bar, (2) click "Profiles" under "Profiles and Policies" heading, (3) click on applicable profile, and (4) choose "Restrictions" in left-hand toolbar. (5) Under Application section uncheck boxes labeled "Allow Google Play", "Allow YouTube", and "Allow Non-Market App Installation".'
  desc 'fix', 'Configure the AirWatch MDM Server so it has the administrative functionality to specify a list of approved applications that must be installed on the mobile device and cannot be removed by the user.

To add blacklist to specific Android device Profile:  (1) click "Add" from the top tool bar, (2) select "Profile" from the drop-down menu, and (3) select "Android".  (4) Choose "Device" or "Container" (Knox), (5) give profile name and insert applicable information under General tab, and on left-hand toolbar (5) select "Application Control".  (6) Click "Configure", (7) check box "Prevent Installation of Blacklisted Apps", and (8) click "Save and Publish".  

To block access to public store on Samsung SAFE devices:  (1) click "Add" from the top tool bar, (2) select "Profile" from the drop-down menu, and (3) select "Android".  (4) Choose "Device" or "Container" (Knox), (5) give profile name and insert applicable information under General tab, and (6) choose "Restrictions" in left-hand toolbar.  (7) Under Application section uncheck boxes labeled "Allow Google Play", "Allow YouTube", and "Allow Non-Market App Installation".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50099r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47333'
  tag rid: 'SV-60205r1_rule'
  tag stig_id: 'ARWA-02-000188'
  tag gtitle: 'SRG-APP-135-MDM-150-MDM'
  tag fix_id: 'F-51039r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
