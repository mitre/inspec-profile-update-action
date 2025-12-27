control 'SV-80211' do
  title 'BlackBerry OS 10.3 must implement the management setting: disallow Personal Space applications access to the Work Space network connection. This requirement does not apply to the Work space only activation type.'
  desc 'Allowing movement of files and data from the personal Space to the Work Space will result in both personal data and sensitive DoD data being placed in the same space. This can potentially result in DoD data being transmitted to non-authorized recipients via personal email accounts or social applications, or transmission of malicious files to DoD accounts. Disabling this feature mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: disallow Personal Space applications access to the Work Space network connection. This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and privacy” group of IT policy rules.
6. Verify "Allow personal apps to use work networks" is not selected.

If the BES IT Policy rule "Allow personal apps to use work networks" is selected, this is a finding.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and privacy” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow personal apps to use work networks".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66377r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65721'
  tag rid: 'SV-80211r1_rule'
  tag stig_id: 'BB10-3X-001010'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71765r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
