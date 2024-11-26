control 'SV-27052' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product.  With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', '# oslevel

Vendor-supported versions are 7.1 and later at the time of writing.

AIX 6.1 End of Support: 30 April 2017

If the release is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36589r5_chk'
  tag severity: 'high'
  tag gid: 'V-11940'
  tag rid: 'SV-27052r2_rule'
  tag stig_id: 'GEN000100'
  tag gtitle: 'GEN000100'
  tag fix_id: 'F-11211r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If an extended support agreement providing security patches for the unsupported product is procured from the vendor, this finding may be downgraded to a CAT III.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
