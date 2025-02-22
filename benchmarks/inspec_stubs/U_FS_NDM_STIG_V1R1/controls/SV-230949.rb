control 'SV-230949' do
  title 'Forescout must prevent the installation of patches, service packs, plug-ins, or modules without verification the update has been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the network device. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and has been provided by a trusted vendor. 

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization. 

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The device should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

Customer portal updates file download section on the vendor website has the MD5 hashes for the updates files.

Currently, this is the method used by DoD to pull down files rather than using the internal connection to the Forescout server.'
  desc 'check', 'Verify by inspecting the SSP or documentation to determine if there is a procedure for validating the MD5 hash against the Forescout updates.forescout.com portal to ensure that the software has come from the Forescout server.

If the site does not have a documented process to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate recognized and approved by the organization, this is a finding.'
  desc 'fix', 'When Forescout updates are downloaded, whether from the DoD update server or the updates.forescout.com portal, each update consists of an MD5 hash. Manually inspect, compare, and verify the MD5 hash against the Forescout website to ensure that the software has come from the Forescout server.'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33879r603686_chk'
  tag severity: 'low'
  tag gid: 'V-230949'
  tag rid: 'SV-230949r615886_rule'
  tag stig_id: 'FORE-NM-000220'
  tag gtitle: 'SRG-APP-000131-NDM-000243'
  tag fix_id: 'F-33852r603687_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
