control 'SV-60201' do
  title 'The AirWatch MDM Server must configure the mobile device agent to prohibit the download of software from a DoD non-approved source (e.g., DoD operated mobile device application store or AirWatch MDM Server).'
  desc 'DoD can perform due diligence on sources of software to mitigate the risk that malicious software is introduced to those sources.  Therefore, if software is downloaded from a DoD-approved source, then it is less likely to be malicious than if it is downloaded from an unapproved source.  To prevent access to unapproved sources, the operating system in most cases can be configured to disable user access to public application stores.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can configure the mobile device agent to prohibit the download of software from a DoD non-approved source (e.g., DoD operated mobile device application store or AirWatch MDM Server). If this function is not present, this is a finding.

Note that the following should take place in conjunction with application blacklisting/whitelisting as noted in "AirWatch iOS Management Guide" page 14 "Securing iOS Devices" and page 30 "Configuring iOS Devices" and applicable items within this STIG.

Apple iOS MOS:
To verify installation of public applications on iOS devices is blocked: from the console ensure that "Device" is selected from left hand tool bar (default screen upon logon), (1) click "Profiles", (2) click "List View", (3) click on applicable profile, and (4) choose "Restrictions" in left-hand toolbar (5) Under Device Functionality section, ensure box labeled "Allow installing public apps" is unchecked.'
  desc 'fix', 'Configure the AirWatch MDM Server so the mobile device agent is configured to prohibit the download of software from a DoD non-approved source.

For iOS devices: (1) click "Add" from the top tool bar, and (2) select "Profile" from the drop-down menu., and (3) select Apple iOS. (4) Give profile name under General tab, and (5) choose "Restrictions" in left-hand toolbar. (6) Under Device Functionality section, uncheck the box labeled "Allow installing public apps".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50095r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47329'
  tag rid: 'SV-60201r1_rule'
  tag stig_id: 'ARWA-02-000186'
  tag gtitle: 'SRG-APP-135-MDM-149-MDM'
  tag fix_id: 'F-51035r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
