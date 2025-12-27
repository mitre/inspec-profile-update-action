control 'SV-80251' do
  title 'BlackBerry OS 10.3 must prevent opening links in work email messages in the personal browser. This requirement only applies to Work and personal - Corporate and Work and personal - Regulated activation types.'
  desc 'If web links in work email were opened using the personal browser, there is a possibility that sensitive DoD data could spill from the Work space to the Personal space, which could lead to public exposure of that data.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry prevents opening links in work email messages in the personal browser.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Apps” group of IT policy rules.
6. Verify "Allow opening links in work email messages in the personal browser" is not selected.

On the BlackBerry device: 
1. Create a test email which, includes a link to a web address, and send it to the work email address on the test device.
2. From the Work Space, open the test email and click on the link.
3. Verify the link opens using the work browser, and no other options are available.

If the BES IT Policy rule "Allow opening links in work email messages in the personal browser" is selected, or on the BlackBerry device if the link can be opened using the personal browser, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies’ tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Apps” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow opening links in work email messages in the personal browser ".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66443r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65761'
  tag rid: 'SV-80251r1_rule'
  tag stig_id: 'BB10-3X-020320'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71831r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
