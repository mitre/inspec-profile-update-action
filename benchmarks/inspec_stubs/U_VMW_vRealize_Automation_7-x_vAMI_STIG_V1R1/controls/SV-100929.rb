control 'SV-100929' do
  title 'The vAMI must be configured to listen on a specific network interface.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', "Obtain the current vRealize Operations STIGs from the ISSO.

Verify that this STIG is the most current STIG available for vRealize Operations. Assess all of the organization's vROps installations to ensure that they are fully compliant with the most current STIG.

If the most current version of the vROps STIG was not used, or if the vROps appliance configuration is not compliant with the most current STIG, this is a finding."
  desc 'fix', 'Obtain the most current vRealize Operations STIG. Verify that this vROps appliance is configured with all current requirements.'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90279'
  tag rid: 'SV-100929r1_rule'
  tag stig_id: 'VRAU-VA-000655'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-97021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
