control 'SV-98863' do
  title 'The vRealize Operations appliance must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the vRealize Operations appliance to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

The vROps product is continually under refinement, and patches are regularly released to address vulnerabilities. As a result, the vROps STIG is also subject to a release cycle on a quarterly basis.

Assessors should ensure that they are reviewing the vRealize Operations appliance with the most current STIG.'
  desc 'check', "Obtain the current vRealize Operations STIGs from the ISSO.

Verify that this Security Technical Implementation Guide (STIG) is the most current STIG available for vRealize Operations.

Assess all of the organization's vROps installations to ensure that they are fully compliant with the most current STIG.

If the most current version of the vROps STIG was not used, or if the vROps appliance configuration is not compliant with the most current STIG, this is a finding."
  desc 'fix', 'Obtain the most current vRealize Operations STIG. Ensure that this vROps appliance is configured with all current requirements.'
  impact 0.5
  ref 'DPMS Target vRealize Operations Manager 6.x Application'
  tag check_id: 'C-87905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88213'
  tag rid: 'SV-98863r1_rule'
  tag stig_id: 'VROM-AP-000655'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-94955r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
