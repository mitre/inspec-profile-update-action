control 'SV-248574' do
  title 'YUM must be configured to prevent the installation of patches, service packs, device drivers, or OL 8 system components that have not been digitally signed using a certificate that is recognized and approved by the organization.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certificate Authority (CA).'
  desc 'check', 'Check that YUM verifies the signature of packages from a repository prior to install with the following command:

$ sudo grep gpgcheck /etc/yum.repos.d/*.repo

gpgcheck=1

If "gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified.

If there is no process to validate certificates that is approved by the organization, this is a finding.'
  desc 'fix', 'Configure OL 8 to verify the signature of packages from a repository prior to install by setting the following option in the "/etc/yum.repos.d/[your_repo_name].repo" file:

gpgcheck=1'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52008r779286_chk'
  tag severity: 'high'
  tag gid: 'V-248574'
  tag rid: 'SV-248574r853753_rule'
  tag stig_id: 'OL08-00-010370'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-51962r779287_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
