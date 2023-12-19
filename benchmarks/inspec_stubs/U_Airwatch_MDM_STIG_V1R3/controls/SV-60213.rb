control 'SV-60213' do
  title 'The AirWatch MDM Server device integrity validation component must employ automated mechanisms to detect the presence of unauthorized software on managed mobile devices and notify designated organizational officials in accordance with the organization-defined frequency.'
  desc 'Unauthorized software poses a risk to the device because it could potentially perform malicious functions, including but not limited to gathering sensitive information, searching for other system vulnerabilities, or modifying log entries.  A mechanism to detect unauthorized software and notify officials of its presence assists in the task of removing such software to eliminate the risks it poses to the device and the networks to which the device attaches.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server device integrity validation component can detect the presence of unauthorized software on managed mobile devices and notify designated organizational officials.  If this function is not present, this is a finding.

To verify Required Application Lists on Administration console:  (1) click on "Menu" in top tool bar, (2) click on "Applications" under "Catalog" heading, on left-hand tool bar (3) click on "Application Groups", (4) click on applicable "Required Applications" Group, and verify that correct information is set.

To verify policies for detecting illegal application via the Compliance Engine, use the following procedure:  (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on applicable compliance policy to verify.  On Rules tab verify the correct rule set for the applicable policy to be applied (first drop-down box should read "Application List", second should read "Contains..." or "Does Not Contain..." and refer to Blacklist/Whitelist/Required application group).  (4) Click "Next".  (5) On Actions tab, verify the correct Action type to take Actionable Result is set (for notification, first drop-down box should read "Notify", second should read "Send Email to Administrator", and third should list applicable email addresses).  (6) On Assignment verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Configure the AirWatch MDM Server device integrity validation component to detect and report the presence of unauthorized software.

To create Required Applications Groups in Administration console:  (1) click on "Menu" in top tool bar, (2) click on "Applications" under "Catalog" heading, and on left-hand tool bar (3) click on "Application Groups", (4) click "Add Group", and under drop-down box labeled "Type" choose "Blacklist".  (5) Choose Android or iOS platform, and (6) add applicable applications. (7) Click "Next" to review summary, and click "Finish". 
 
To establish application group policies for the Compliance Engine, use the following procedure:  (1) click "Add" from the top tool bar, and (2) click "Compliance Policy".  On Rules tab, (3) select to Match "All" or "Any" of the entered Rules, (4) in first drop-down box select "Application List", (5) denote group rule (if MOS contains/does not contain Whitelisted/ Blacklisted/ Required applications), and (6) click "Next".  (7) On Actions tab, (8) select "Notify" in first drop-down box, (9) select "Send Email to Administrator" in second drop-down box, and (10) enter in applicable email addresses for notification in "To:" box.  (11) Click "Next".  On Assignment tab (12) select device types, users, or groups to assign Policy to, and (13) click "Next".  (14) View Summary for accuracy, and (15) click "Save and Assign".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-47341'
  tag rid: 'SV-60213r1_rule'
  tag stig_id: 'ARWA-01-000177'
  tag gtitle: 'SRG-APP-189-MDM-168-MDIS'
  tag fix_id: 'F-51047r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001069']
  tag nist: ['RA-5 (7)']
end
