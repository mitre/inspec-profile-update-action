control 'SV-254191' do
  title 'Nutanix AOS must prevent the installation of patches, service packs, device drivers, or operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Confirm that Nutanix AOS is configured to require gpgcheck and localpkg_gpgcheck for all installation packages provided by the vendor.

$ sudo grep gpgcheck /etc/yum.conf
gpgcheck=1

$ sudo grep localpkg_gpgcheck /etc/yum.conf
localpkg_gpgcheck=1

$ sudo grep repo_gpgcheck /etc/yum.conf
repo_gpgcheck=1

If any of the three gpg checks output is not set to "1", this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to require gpgcheck validation checks on all required yum repo configurations by running the following command:

$ sudo salt-call state.sls security/CVM/yumCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57676r846659_chk'
  tag severity: 'medium'
  tag gid: 'V-254191'
  tag rid: 'SV-254191r846661_rule'
  tag stig_id: 'NUTX-OS-001040'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-57627r846660_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
