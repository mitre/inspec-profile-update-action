control 'SV-80199' do
  title 'BlackBerry OS 10.3 must implement the management setting: limit Work Space contact data available in Personal space.'
  desc "The contact database often contains a significant amount of information beyond each person's name and phone number. The records may contain addresses and other identifying or sensitive information that should not be revealed. There may be cases in which an organization has determined it is an acceptable risk to distribute parts of a person's contact record but not others. Enabling the system administrator to select which fields are available outside the contact database application (or to applications outside the work persona in the case of a dual persona device) assists with management of the risk.

SFR ID: FMT_SMF_EXT.1.1 #45"
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry limits Work Space contact data available in Personal space. This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the "IT policies" tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Allow personal apps to access work contacts" is set to "Only BlackBerry Apps".

If the BES IT policy rule "Allow personal apps to access work contacts" is not set to "Only BlackBerry Apps", this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Set the IT Policy "Allow personal apps to access work contacts" to "BlackBerry Apps Only".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66363r4_chk'
  tag severity: 'medium'
  tag gid: 'V-65709'
  tag rid: 'SV-80199r1_rule'
  tag stig_id: 'BB10-3X-000930'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
