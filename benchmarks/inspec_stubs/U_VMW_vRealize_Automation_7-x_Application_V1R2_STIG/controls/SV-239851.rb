control 'SV-239851' do
  title 'The vRealize Automation appliance must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the vRealize Automation application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

The vRA product is continually under refinement, and patches are regularly released to address vulnerabilities. As a result, the vRA STIG is also subject to a release cycle on a quarterly basis.

Assessors should ensure that they are reviewing the vRealize Automation appliance with the most current STIG.'
  desc 'check', "Obtain the current vRealize Automation STIGs from the ISSO.

Verify that this STIG is the most current STIG available for vRealize Automation. Assess all of the organization's vRA installations to ensure they are fully compliant with the most current STIG.

If the most current version of the vRA STIG was not used, or if the vRA appliance configuration is not compliant with the most current STIG, this is a finding."
  desc 'fix', 'Obtain the most current vRealize Automation STIG. Verify that this vRA appliance is configured with all current requirements.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Application'
  tag check_id: 'C-43084r664467_chk'
  tag severity: 'medium'
  tag gid: 'V-239851'
  tag rid: 'SV-239851r879887_rule'
  tag stig_id: 'VRAU-AP-000655'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-43043r664468_fix'
  tag 'documentable'
  tag legacy: ['SV-99787', 'V-89137']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
