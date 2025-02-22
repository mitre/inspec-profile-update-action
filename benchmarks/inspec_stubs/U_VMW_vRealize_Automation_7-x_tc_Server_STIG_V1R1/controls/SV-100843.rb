control 'SV-100843' do
  title 'tc Server ALL must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the web server to implement organization-wide security implementation guides and security checklists guarantees compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the web server, including the parameters required to satisfy other security control requirements.

VMware delivers product updates and patches regularly. It is crucial that system administrators coordinate installation of product updates with the site ISSO to ensure that updated and patched files are uploaded onto the system as soon as prescribed.'
  desc 'check', "Interview the ISSO.

Verify that this Security Technical Implementation Guide (STIG) is the most current STIG available for tc Server on vRA. Assess all of the organization's vRA installations to ensure that they are fully compliant with the most current tc Server STIG.

If the most current version of the tc Server was not used, or if the tc Server configuration is not compliant with the most current tc Server STIG, this is a finding."
  desc 'fix', 'Obtain the most current tc Server ALL STIG. Verify that tc Server ALL is configured with all current requirements.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90193'
  tag rid: 'SV-100843r1_rule'
  tag stig_id: 'VRAU-TC-000960'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-96935r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
