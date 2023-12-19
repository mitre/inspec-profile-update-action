control 'SV-224669' do
  title 'The Red Hat Enterprise Linux operating system must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

The Red Hat Enterprise Linux (RHEL) Extended Life Cycle Support Add-On (ELS) is an offering, for a fee, that provides extended support once a product is retired and has entered the Extended Life Phase. ELS allows customers to continue to receive critical impact security fixes and selected urgent priority bug fixes on a specific major version of RHEL from the end of its regular life cycle for an extended and defined period. ELS is only applicable to the last minor release of the given major release.'
  desc 'check', 'Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

# cat /etc/redhat-release

Red Hat Enterprise Linux Server release 6.10 (Santiago)

Current end of maintenance support for RHEL 6.10 is 30 November 2020.

If the release is not supported by the vendor, this is a finding.

Note: RHEL ELS is available for RHEL 6.10 with a proposed end of support 30 June 2024.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-26358r462501_chk'
  tag severity: 'high'
  tag gid: 'V-224669'
  tag rid: 'SV-224669r603264_rule'
  tag stig_id: 'RHEL-06-000010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-26346r462502_fix'
  tag 'documentable'
  tag legacy: ['SV-111391', 'V-102441']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
