control 'SV-80245' do
  title 'BlackBerry OS 10.3 must implement the management setting: display External Email Address Warning Message.'
  desc 'The "External Email Address Warning Message" allows administrators to enforce a feature on the BlackBerry 10 smartphones to display a warning message for email addresses that are deemed as external to the primary internal mail domain. This feature provides a safeguard for accidently sending sensitive DoD information to email addresses external to the DoD.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: display External Email Address Warning Message. This procedure is performed on both the BES console and BlackBerry device.

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Apps” group of IT policy rules.
6. Verify "Display indicator for external email addresses" is selected.

On the BlackBerry device:
1. Open the email application and select "Compose".
2. In the "to" field, enter an email address for an external contact.
3. As you type email address, verify "(External Address - Not recommended)" is displayed.
4. After completing email address, email address should be highlighted in red.

If the BES IT Policy rule "Display indicator for external email addresses" is not selected, or on the BlackBerry device a warning indicator is not received (as described above), this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Apps” group of IT policy rules.
7. Select the check box next to the IT Policy "Display indicator for external email addresses".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66435r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65755'
  tag rid: 'SV-80245r1_rule'
  tag stig_id: 'BB10-3X-020280'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71823r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
