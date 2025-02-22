control 'SV-80241' do
  title 'The BlackBerry MDM Agent must be configured to synchronize generated audit records of required events every 6 hours or less. This requirement only applies to Work space only and Work and personal - Regulated activation types and to version 10.3.3 and later of the BlackBerry OS.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks, so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security.

SFR ID: FAU_GEN.1.1(2) Refinement, MDM Agent EP'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry is configured to synchronize generated audit records of required events every "6 hours" or less. This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Event log synchronization frequency" is set to "6 hours" or less.

If the BES IT policy rule Event log synchronization frequency" is not set to "6 hours" or less, this is a finding.

Note: Procedures above are for BES 12 only, and is not available on BES 10.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Select the check box next to the IT Policy "Event logging".
8. Set "Event log synchronization frequency" to "6 hours" or less.
9. Click "Save".

Note: Procedures above are for BES 12 only, and is not available on BES 10.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66431r2_chk'
  tag severity: 'low'
  tag gid: 'V-65751'
  tag rid: 'SV-80241r2_rule'
  tag stig_id: 'BB10-3X-020270'
  tag gtitle: 'PP-MDM-203001'
  tag fix_id: 'F-71819r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
