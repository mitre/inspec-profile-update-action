control 'SV-239607' do
  title 'The RPM package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or SLES for vRealize components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. SLES for vRealize should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.'
  desc 'check', 'Verify RPM signature validation is not disabled:

# grep nosignature /usr/lib/rpm/rpmrc ~root/.rpmrc

The result should either respond with no such file or directory, or an empty return.

If any configuration is found, this is a finding.'
  desc 'fix', 'Edit the RPM configuration files containing the "nosignature" option and remove the option.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42840r662270_chk'
  tag severity: 'medium'
  tag gid: 'V-239607'
  tag rid: 'SV-239607r877463_rule'
  tag stig_id: 'VROM-SL-001145'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-42799r662271_fix'
  tag 'documentable'
  tag legacy: ['SV-99335', 'V-88685']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
