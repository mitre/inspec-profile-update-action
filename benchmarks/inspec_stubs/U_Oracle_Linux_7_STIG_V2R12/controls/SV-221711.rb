control 'SV-221711' do
  title 'The Oracle Linux operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that yum verifies the signature of local packages prior to install with the following command:

# grep localpkg_gpgcheck /etc/yum.conf
localpkg_gpgcheck=1

If "localpkg_gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the signatures of local packages and other operating system components are verified. 

If there is no process to validate the signatures of local packages that is approved by the organization, this is a finding.'
  desc 'fix', 'Configure the operating system to verify the signature of local packages prior to install by setting the following option in the "/etc/yum.conf" file:

localpkg_gpgcheck=1'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23426r462704_chk'
  tag severity: 'high'
  tag gid: 'V-221711'
  tag rid: 'SV-221711r877463_rule'
  tag stig_id: 'OL07-00-020060'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-23415r462705_fix'
  tag 'documentable'
  tag legacy: ['V-99161', 'SV-108265']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
