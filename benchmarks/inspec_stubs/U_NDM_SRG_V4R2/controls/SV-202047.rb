control 'SV-202047' do
  title 'The network device must prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the network device. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The device should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Determine if the network device prevents the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization. This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization, this is a finding.'
  desc 'fix', 'Configure the network device to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2173r381746_chk'
  tag severity: 'medium'
  tag gid: 'V-202047'
  tag rid: 'SV-202047r879584_rule'
  tag stig_id: 'SRG-APP-000131-NDM-000243'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-2174r381747_fix'
  tag 'documentable'
  tag legacy: ['SV-69465', 'V-55219']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
