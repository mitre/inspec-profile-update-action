control 'SV-218188' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product.  With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Check the version of the operating system.

Example:
# cat /etc/oracle-release

Vendor End-of-Support Information:

Oracle Linux 5 premier support ends on March 2017, but sustaining support continues indefinitely.  For more information, see the Oracle Lifetime Support Policy for Oracle Linux at: http://www.oracle.com/us/support/library/elsp-lifetime-069338.pdf.

Check with the vendor for additional information.

If the version installed is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19663r553901_chk'
  tag severity: 'high'
  tag gid: 'V-218188'
  tag rid: 'SV-218188r603259_rule'
  tag stig_id: 'GEN000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19661r553902_fix'
  tag 'documentable'
  tag legacy: ['V-11940', 'SV-63095']
  tag cci: ['CCI-000366', 'CCI-001230']
  tag nist: ['CM-6 b', 'SI-2 d']
end
