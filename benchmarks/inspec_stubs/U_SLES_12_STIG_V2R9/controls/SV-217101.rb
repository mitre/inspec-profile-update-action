control 'SV-217101' do
  title 'The SUSE operating system must be a vendor-supported release.'
  desc 'A SUSE operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Verify the SUSE operating system is a vendor-supported release.

Use the following command to verify the SUSE operating system is a vendor-supported release:

# cat /etc/os-release

NAME="SLES"

VERSION="12"

Current End of Life for SLES 12 General Support is 31 Oct 2024 and Long-term Support is until 31 Oct 2027.

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade the SUSE operating system to a version supported by the vendor. If the system is not registered with the SUSE Customer Center, register the system against the correct subscription.

If the system requires Long-Term Service Pack Support (LTSS), obtain the correct LTSS subscription for the system.'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18329r369459_chk'
  tag severity: 'high'
  tag gid: 'V-217101'
  tag rid: 'SV-217101r603262_rule'
  tag stig_id: 'SLES-12-010000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18327r369460_fix'
  tag 'documentable'
  tag legacy: ['V-77045', 'SV-91741']
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
