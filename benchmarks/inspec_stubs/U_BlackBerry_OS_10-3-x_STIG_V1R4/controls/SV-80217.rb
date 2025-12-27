control 'SV-80217' do
  title 'The BlackBerry MDM Agent must be configured to operate in a NIAP Common Criteria mode of operation, to enable generation of audit records of required events: (See Vulnerability Discussion for list). This requirement only applies to Work space only and Work and personal - Regulated activation types.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks, so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security.

Required audit events:
a. Start-up and shutdown of the audit functions;
b. Change in MDM policy;
c. Device modification commanded by the MDM server;
d. Specifically defined auditable events in Table 7 of MDM Agent EP v.2.0.

SFR ID: FAU_GEN.1.1(2) Refinement, MDM Agent EP'
  desc 'check', 'Review BlackBerry OS 10.3 configuration settings to determine if the BlackBerry is configured to operate in a NIAP Common Criteria mode of operation, to enable generation of an audit record of required events for Start-up and shutdown of the audit functions, Change in MDM policy, Device modification commanded by the MDM server, and Specifically defined auditable events in Table 7 of MDM Agent EP v.2.0. This procedure is performed on only on the BES console.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Scroll down to the “Security and Privacy” group of IT policy rules.
6. Verify "Enable NIAP Common Criteria functionality" is selected.

If the BES IT policy rule "Enable NIAP Common Criteria functionality" is not selected, this is a finding.

Note: Procedures above are for BES 12 only, and is not available on BES 10.'
  desc 'fix', 'On the BES 12, do the following:
1. Log into the BES 12 console and select the "POLICIES AND PROFILES” tab at the top of the screen.
2. Expand the “IT policies” tab on the left pane.
3. Select and open each IT policy assigned to users in turn.
4. After opening the policy, select the “Settings” and “BlackBerry” tabs.
5. Click the pencil icon (upper right corner) to edit the IT Policy.
6. Scroll down to the “Security and Privacy” group of IT policy rules.
7. Select the check box next to the IT Policy "Enable NIAP Common Criteria functionality".
8. Click "Save".

Note: Procedures above are for BES 12 only, and is not available on BES 10.'
  impact 0.3
  ref 'DPMS Target BlackBerry OS 10.3.x'
  tag check_id: 'C-66383r3_chk'
  tag severity: 'low'
  tag gid: 'V-65727'
  tag rid: 'SV-80217r1_rule'
  tag stig_id: 'BB10-3X-020200'
  tag gtitle: 'PP-MDM-203001'
  tag fix_id: 'F-71771r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
