control 'SV-80253' do
  title 'BlackBerry OS 10.3 must prevent untrusted connections to the mail server.'
  desc 'If an untrusted connection to a mail server is allowed, the device may connect to either a rogue email server or a compromised DoD email server. In either case, sensitive DoD data could be compromised.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry prevents untrusted connections to the mail server. This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Apps” group of IT policy rules.
6. Verify "Allow untrusted connections to the mail server" is not selected.

If the BES IT Policy rule "Allow untrusted connections to the mail server" is selected, this is a finding.

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Apps” group of IT policy rules.
7. Unselect the check box next to the IT Policy "Allow untrusted connections to the mail server".
8. Click "Save".

Note: Procedures above are for BES 12 only. BES 10 procedures may be slightly different.'
  impact 0.5
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66445r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65763'
  tag rid: 'SV-80253r1_rule'
  tag stig_id: 'BB10-3X-020330'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-71833r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
