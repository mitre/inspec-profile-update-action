control 'SV-222513' do
  title 'The application must have the capability to prevent the installation of patches, service packs, or application components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the application. Verifying software components have been digitally signed using a certificate that is recognized and approved by the organization ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, or application components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The application should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

If this capability is not present, the vendor must provide a cryptographic hash value that can be verified by a system administrator prior to installation.'
  desc 'check', 'Review the application documentation and interview the application administrator to determine the process and commands used for patching the application.

Access application configuration settings.

Review commands and procedures used to patch the application and ensure a capability exists to prevent unsigned patches from being applied.

If the application is not capable of preventing installation of patches and packages that are not signed, or if the vendor does not provide a cryptographic hash value that can be manually checked prior to installation, this is a finding.'
  desc 'fix', 'Design and configure the application to have the capability to prevent unsigned patches and packages from being installed.

Provide a cryptographic hash value that can be verified by a system administrator prior to installation.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24183r561246_chk'
  tag severity: 'medium'
  tag gid: 'V-222513'
  tag rid: 'SV-222513r561248_rule'
  tag stig_id: 'APSC-DV-001430'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-24172r561247_fix'
  tag 'documentable'
  tag legacy: ['SV-84131', 'V-69509']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
