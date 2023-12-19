control 'SV-60193' do
  title 'The AirWatch MDM Server must configure the mobile device to prohibit the mobile device user from installing unapproved applications.'
  desc 'The operating system must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.  The installation and execution of unauthorized software on an operating system may allow the application to obtain sensitive information or further compromise the system.  Preventing a user from installing unapproved applications mitigates this risk.  All OS core applications, third-party applications, and carrier installed applications must be approved.  In this case, applications include any applets, browse channel apps, and icon apps.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can configure the mobile device to prohibit the mobile device user from installing unapproved applications. If this function is not present, this is a finding.

Note that the following should take place in conjunction with application blacklisting/whitelisting as noted in the "AirWatch Samsung Management Guide" page 8 "Securing Samsung Devices" and page 17 "Configuring Samsung Devices", and applicable items within this STIG.

Samsung Knox MOS:
To verify Blacklist on specific Android device profile: (1) click "Menu" from top tool bar, (2) click "Profiles" under "Profiles and Policies" heading, (3) click on applicable Profile, and (4) on left-hand toolbar select "Application Control". (5) Ensure box "Prevent Installation of Blacklisted Apps" is checked.

To verify access to public store on Samsung SAFE devices is blocked: (1) click "Menu" from top tool bar, (2) click "Profiles" under "Profiles and Policies" heading, (3) click on applicable profile, and (4) choose "Restrictions" in left-hand toolbar. (5) Under Application section ensure boxes labeled "Allow Google Play", "Allow YouTube", and "Allow Non-Market App Installation" are unchecked.'
  desc 'fix', 'Configure the AirWatch MDM Server so the mobile device is configured to prohibit the mobile device user from installing unapproved applications.

To add Blacklist to specific Android device Profile: (1) click "Add" from the top tool bar, (2) select "Profile" from the drop-down menu, and (3) select "Android". (4) Choose "Device" or "Container" (Knox), (5) give profile name and insert applicable information under General tab, and (6) on left-hand toolbar select "Application Control". (7) Click "Configure", (8) check box "Prevent Installation of Blacklisted Apps", and (9) click "Save and Publish".

To block access to public store on Samsung SAFE devices: 1) click "Add" from the top tool bar, (2) select "Profile" from the drop-down menu, and (3) select "Android". (4) Choose "Device" or "Container" (Knox), (5) give profile name and insert applicable information under General tab, and (6) choose "Restrictions" in left-hand toolbar. (7) Under Application section uncheck boxes labeled "Allow Google Play", "Allow YouTube", and "Allow Non-Market App Installation".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50087r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47321'
  tag rid: 'SV-60193r1_rule'
  tag stig_id: 'ARWA-02-000182'
  tag gtitle: 'SRG-APP-135-MDM-148-MAM'
  tag fix_id: 'F-51027r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
