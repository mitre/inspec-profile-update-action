control 'SV-233274' do
  title 'The container platform must be able to store and instantiate industry standard container images.'
  desc 'Monitoring the container images and containers during their lifecycle is important to guarantee the container platform is secure. To monitor the containers and images, security tools can be put in place. To fully utilize the security tools available, using images formatted in an industry standard format should be used. This allows the tools to fully understand the images and containers. One standard being worked on by industry leaders in the container space is the Open Container Initiative (OCI). This group is developing a standard container image format.'
  desc 'check', 'Review the container platform configuration and documentation to determine if the platform is configured to store and instantiate industry standard container images. 

If the container platform cannot instantiate industry standard container images, this is a finding.'
  desc 'fix', 'Enable the container platform to store and instantiate industry standard container image formats.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36210r601887_chk'
  tag severity: 'medium'
  tag gid: 'V-233274'
  tag rid: 'SV-233274r601854_rule'
  tag stig_id: 'SRG-APP-000516-CTR-001330'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-36178r601310_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
