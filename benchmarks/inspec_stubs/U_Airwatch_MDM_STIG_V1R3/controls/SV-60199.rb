control 'SV-60199' do
  title 'The AirWatch MDM Server must configure the mobile device agent to prohibit the download of software from a DoD non-approved source (e.g., DoD operated mobile device application store or AirWatch MDM Server).'
  desc 'DoD can perform due diligence on sources of software to mitigate the risk that malicious software is introduced to those sources.  Therefore, if software is downloaded from a DoD-approved source, then it is less likely to be malicious than if it is downloaded from an unapproved source.  To prevent access to unapproved sources, the operating system in most cases can be configured to disable user access to public application stores.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can configure the mobile device agent to prohibit the download of software from a DoD non-approved source (e.g., DoD operated mobile device application store or AirWatch MDM Server). If this function is not present, this is a finding.

Note that the following should take place in conjunction with application blacklisting/whitelisting as noted in the "AirWatch Samsung Management Guide" page 8 "Securing Samsung Devices" and page 17 "Configuring Samsung Devices", and applicable items within this STIG.

Samsung Knox MOS:
To verify installation of public applications on Samsung Knox devices is blocked: (1) click "Menu" from top tool bar, (2) click "Profiles" under "Profiles and Policies" heading, (3) click on applicable Profile, and (4) choose "Restrictions" in left-hand toolbar. (5) Under Application section ensure boxes labeled "Allow Google Play", "Allow YouTube", and "Allow Non-Market App Installation" are unchecked.'
  desc 'fix', 'Configure the AirWatch MDM Server so the mobile device agent is configured to prohibit the download of software from a DoD non-approved source.

For Samsung Knox devices: (1) click "Add" from the top tool bar, (2) select "Profile" from the drop-down menu, and (3) select "Android". (4) Choose "Device" or "Container" (Knox), (5) give Profile name and insert applicable information under General tab, and (6) choose "Restrictions" in left-hand toolbar. (7) Under Application section uncheck boxes labeled "Allow Google Play", "Allow YouTube", and "Allow Non-Market App Installation".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50093r3_chk'
  tag severity: 'medium'
  tag gid: 'V-47327'
  tag rid: 'SV-60199r1_rule'
  tag stig_id: 'ARWA-02-000185'
  tag gtitle: 'SRG-APP-135-MDM-149-MDM'
  tag fix_id: 'F-51033r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
