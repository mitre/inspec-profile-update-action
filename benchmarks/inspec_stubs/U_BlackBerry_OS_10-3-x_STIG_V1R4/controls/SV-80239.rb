control 'SV-80239' do
  title 'BlackBerry OS 10.3 must force the use of BBM Protected mode.'
  desc 'BBM Protected mode provides strong data encryption for the Blackberry chat service. If data-in-transit is unencrypted, it is vulnerable to disclosure.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry forces the use of BBM Protected mode. This procedure is performed on only on the BES console

Note: If an organization has multiple configuration profiles, then the Implementation procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Use BBM Protected" is selected.

If the BES IT Policy rule "Use BBM Protected" is not selected, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Select the check box next to the IT Policy "Use BBM Protected".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66427r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65749'
  tag rid: 'SV-80239r1_rule'
  tag stig_id: 'BB10-3X-020265'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71815r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
