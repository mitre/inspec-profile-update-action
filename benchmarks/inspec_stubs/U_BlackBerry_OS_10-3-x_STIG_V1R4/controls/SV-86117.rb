control 'SV-86117' do
  title 'The BlackBerry OS 10.3 smartphone must implement the management setting:  Allow use of preloaded trusted root certificates'
  desc 'This configuration setting specifies whether a BlackBerry device can use preloaded trusted root certificates to establish a trusted certificate chain. If this rule is not selected, the device can use only trusted root certificates that are sent from BES12 for work connections.  When not selected, the DoD will be limited in how root certificates can be deployed to BlackBerry handhelds, which may cause an operational issue.'
  desc 'check', 'Review the BlackBerry OS 10.3 smartphone configuration settings to determine if the BlackBerry implements the management setting:  Allow use of preloaded trusted root certificates.  This procedure is performed on only on the BES console

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the side of the screen.
2. Expand the "IT policies" tab on the left pane.
3. Select and open each IT policy assigned to users, in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and privacy” group of IT policy rules
6. Verify "Allow use of preloaded trusted root certificates" is selected.

If the BES IT policy rule "Allow use of preloaded trusted root certificates" is not selected, this is a finding. 

Note:  Procedures above are for BES 12 only.  BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the side of the screen.
2. Expand the "IT policies" tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click "pencil icon" (upper right corner) to edit the IT Policy.
6. Scroll down to the “Device Functionality” group of IT policy rules
7. Select the checkbox next to the IT Policy "Allow use of preloaded trusted root certificates".
8. Click "Save".

Note:  Procedures above are for BES 12 only.  BES 10 procedures may be slightly different.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-71883r2_chk'
  tag severity: 'low'
  tag gid: 'V-71493'
  tag rid: 'SV-86117r1_rule'
  tag stig_id: 'BB10-3X-001070'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-77813r2_fix'
  tag 'documentable'
end
