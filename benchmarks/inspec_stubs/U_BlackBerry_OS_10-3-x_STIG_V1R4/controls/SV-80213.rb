control 'SV-80213' do
  title 'BlackBerry OS 10.3 must implement the management setting: disable BlackBerry Bridge.'
  desc 'BlackBerry Bridge is used to view information on the BlackBerry via the BlackBerry Playbook tablet. Use of the BlackBerry Playbook is not allowed in the DoD, therefore BlackBerry Bridge must be disabled.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry implements the management setting: disable BlackBerry Bridge. This procedure is performed on only on the BES console.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Allow BlackBerry Bridge to access the work space" is not selected.

If the BES IT Policy rule "Allow BlackBerry Bridge to access the work space" is selected, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Edit.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow BlackBerry Bridge to access the work space".
8. Click "Save".

Note: Procedures above are for BES 12 only.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66379r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65723'
  tag rid: 'SV-80213r1_rule'
  tag stig_id: 'BB10-3X-001040'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71767r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
