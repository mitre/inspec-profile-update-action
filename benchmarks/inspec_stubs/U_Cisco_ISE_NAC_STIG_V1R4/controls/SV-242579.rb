control 'SV-242579' do
  title 'The Cisco ISE must verify anti-malware software is installed and up to date on posture required clients defined in the NAC System Security Plan (SSP) prior to granting trusted network access. This is required for compliance with C2C Step 4.'
  desc 'New viruses and malware are consistently being discovered. If the host-based security software is not current then it will not be able to defend against exploits that have been previously discovered.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify that the posture policy will verify that anti-malware software is installed and up to date.

If not required by the NAC SSP, this is not a finding.

1. Navigate to Work Center >> Posture >> Posture Policy.
2. Look over the enabled posture policies analyzing all the conditions.
3. Review the requirements listed on polices that the posture required clients will use.
4. Navigate to Work Center >> Posture >> Policy Elements.
5. Review the requirements applied in the posture policy to ensure there are with anti-malware conditions applied.
6. Review the anti-malware conditions ensuring one is configured to verify that the software is installed, and one is configured to make sure the software is up to date. 

If this requirement is meet by another system or application, this is not applicable. 

If there is not a firewall condition tied to a requirement that is applied to an applicable posture policy, this is a finding.'
  desc 'fix', %q(If required by the NAC SSP, configure the posture policy to verify that an anti-malware software is up to date.

1. Navigate to Work Centers >> Posture >> Policy Elements.

2. Create Anti-Malware Condition.
a. Expand "Conditions" on the left of the page.
b. Choose "Anti-Malware".
c. Choose "Add".
d. Define a Name.
e. Select the Operating System.
f. Select the vendor.
g. Check "Definition".
h. Check "Check against latest AV definition file version if available. Otherwise check against latest definition file date." or "Allow virus definition file to be (<1) days older than the current system date." 
i. Select the desired product/products.
j. Choose "Submit".

3. Create Anti-Malware Remediation.
a. Expand "Remediation's" on the left of the page.
b. Choose "Anti-Malware".
c. Choose "Add".
d. Define a Name.
e. Select the Operating System.
f. Select the Remediation Type.
g. Define the interval between retries.
h. Define Retry Count.
i. Select the desired Vendor Name.
j. Check "Remediation Option is to enable the Firewall".
k. Select the Product Name.
l. Choose "Submit".

4. Edit the Posture Policy.
a. Navigate to Work Centers >> Posture >> Posture Policy.
b. Find the Posture Policy that will be applied to the posture required endpoints.
c. Select the Requirement ensuring there is a green check box to the left of the name indicating it is a mandatory requirement.
d. Choose "Done".
e. Choose "Save".

Note: If any other Definition option is used, the Posture Updates must be updated (Navigate to Work Centers >> Posture >> Settings >> Software Updates >> Posture Updates).

Configure the posture policy to verify that an anti-malware software is installed.
1. Navigate to Work Centers >> Posture >> Policy Elements.

2. Create Anti-Malware Condition.
a. Expand "Conditions" on the left of the page.
b. Choose "Anti-Malware".
c. Choose "Add".
d. Define a Name.
e. Select the Operating System.
f. Select the vendor.
g. Check "Installation".
h. Select the desired product/products.
i. Choose "Submit".

3. Create Anti-Malware Remediation.
a. Expand "Remediation's" on the left of the page.
b. Choose "Anti-Malware".
c. Choose "Add".
d. Define a Name.
e. Select the Operating System.
f. Select the Remediation Type.
g. Define the interval between retries.
h. Define Retry Count.
i. Select the desired Vendor Name.
j. Check "Remediation Option is to enable the Firewall".
k. Select the Product Name.
l. Choose "Submit".

4. Edit the Posture Policy.
a. Navigate to Work Centers >> Posture >> Posture Policy.
b. Find the Posture Policy that will be applied to the posture required endpoints.
c. Select the Requirement ensuring there is a green check box to the left of the name indicating it is a mandatory requirement.
d. Choose "Done".
e. Choose "Save".)
  impact 0.7
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45854r812739_chk'
  tag severity: 'high'
  tag gid: 'V-242579'
  tag rid: 'SV-242579r812740_rule'
  tag stig_id: 'CSCO-NC-000050'
  tag gtitle: 'SRG-NET-000015-NAC-000020'
  tag fix_id: 'F-45811r803523_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
