control 'SV-44761' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product.  With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Check the version of the operating system.

Example:
# cat /etc/SuSE-release
-	OR – (if more detail is required)
# sam --no-rpm-verify-md5 --spreport
Vendor End-of-Support Information:
SUSE Linux Enterprise Server  9:  31 Aug 2011
SUSE Linux Enterprise Server 10:  31 Jul 2013
SUSE Linux Enterprise Server 11:  31 Mar 2016

Check with the vendor for additional information.

If the version installed is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42266r1_chk'
  tag severity: 'high'
  tag gid: 'V-11940'
  tag rid: 'SV-44761r1_rule'
  tag stig_id: 'GEN000100'
  tag gtitle: 'GEN000100'
  tag fix_id: 'F-38211r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If an extended support agreement provides security patches for the unsupported product is procured from the vendor, this finding may be downgraded to a CAT III.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
