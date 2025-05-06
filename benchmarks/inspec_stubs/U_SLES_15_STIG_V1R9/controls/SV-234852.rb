control 'SV-234852' do
  title 'The SUSE operating system tool zypper must have gpgcheck enabled.'
  desc 'Changes to any software components can have significant effects on the overall security of the SUSE operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

Accordingly, patches, service packs, device drivers, or SUSE operating system components must be signed with a certificate recognized and approved by the organization.

Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The SUSE operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certification Authority (CA).'
  desc 'check', %q(Verify that the SUSE operating system tool zypper has gpgcheck enabled.

Check that zypper has gpgcheck enabled with the following command: 

> grep -i '^gpgcheck' /etc/zypp/zypp.conf

gpgcheck = 1

If "gpgcheck" is set to "0", "off", "no", or "false", this is a finding.)
  desc 'fix', 'Configure that the SUSE operating system tool zypper to enable gpgcheck by editing or adding the following line to "/etc/zypp/zypp.conf":

gpgcheck = 1'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38040r618825_chk'
  tag severity: 'high'
  tag gid: 'V-234852'
  tag rid: 'SV-234852r877463_rule'
  tag stig_id: 'SLES-15-010430'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-38003r618826_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
