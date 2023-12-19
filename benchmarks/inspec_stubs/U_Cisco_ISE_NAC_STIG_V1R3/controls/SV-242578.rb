control 'SV-242578' do
  title 'The Cisco ISE must verify host-based firewall software is running on posture required clients defined in the NAC System Security Plan (SSP) prior to granting trusted network access. This is required for compliance with C2C Step 4.'
  desc "Automated policy assessments must reflect the organization's current security policy so entry control decisions will happen only where remote endpoints meet the organization's security requirements. If the remote endpoints are allowed to connect to the organization's network without passing minimum-security controls, they become a threat to the entire network."
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.
If host-based firewall is not required by the NAC SSP, this is not a finding.

Verify that the posture policy will verify that a host-based firewall is running.

1. Navigate to Work Center >> Posture >> Posture Policy.
2. Review the enabled posture policies analyzing all the conditions.
3. Review the requirements listed on polices that the posture required clients will use.
4. Navigate to Work Center >> Posture >> Policy Elements.
5. Review the requirements applied in the posture policy to ensure there is one with a firewall condition applied.
6. Review the firewall condition ensuring it is configured to verify that the client firewall is enabled.

If there is not a firewall condition tied to a requirement that is applied to an applicable posture policy, this is a finding.'
  desc 'fix', %q(If required by the sites' NAC SSP, configure the posture policy to verify that a host-based firewall is running.

1. Navigate to Work Centers >> Posture >> Policy Elements.

2. Create Firewall Condition.
a. Expand "Conditions" on the left of the page.
b. Choose "Firewall Condition".
c. Choose "Add".
d. Define a Name.
e. Select the applicable Compliance Module.
f. Select the Operating System.
g. Select the vendor of firewall.
h. Check "enable".
i. Select the desired product/products.
j. Choose "Save".

3. Create Firewall Remediation.
a. Expand "Remediation's" on the left of the page.
b. Choose "Firewall".
c. Choose "Add".
d. Define a Name.
e. Select the Operating System.
f. Select the applicable Compliance Module.
g. Select the Remediation Type.
h. Define the interval between retries.
i. Define Retry Count.
j. Select the desired Vendor Name.
k. Check "Remediation Option is to enable the Firewall".
l. Select the Product Name.
m. Choose "Submit".

4. Create Requirements.
a. Choose "Requirements" on the left of the page.
b. Choose the drop-down located next to "Edit" on the right side of the page where the requirement is to be inserted.
c. Choose "Insert new Requirement".
d. Define a Name.
e. Select the Operating System.
f. Select the applicable Compliance Module.
g. Select the Posture Type.
h. Select the Condition previously configured.
i. Select the Remediation Action previously configured and type in a message to display.
j. Choose "Done".
k. Choose "Save".

5. Edit the Posture Policy.
a. Navigate to Work Centers >> Posture >> Posture Policy.
b. Find the Posture Policy that will be applied to the posture required endpoints.
c. Select the Requirement ensuring there is a green check box to the left of the name indicating it is a mandatory requirement.
d. Choose "Done".
e. Choose "Save".)
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45853r812737_chk'
  tag severity: 'high'
  tag gid: 'V-242578'
  tag rid: 'SV-242578r812738_rule'
  tag stig_id: 'CSCO-NC-000040'
  tag gtitle: 'SRG-NET-000015-NAC-000020'
  tag fix_id: 'F-45810r803520_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
