control 'SV-226430' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered supported if the vendor continues to provide security patches for the product.  With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', '# uname -a

Oracle has committed to indefinite "sustaining support" for recent Solaris operating system releases.  Verify proof of purchase of support from Oracle.

If the release is not supported, this is a finding.

Severity Override Guidance:
If an extended support agreement provides security patches for the unsupported product is procured from the vendor, this finding may be downgraded to a CAT III.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36370r602713_chk'
  tag severity: 'high'
  tag gid: 'V-226430'
  tag rid: 'SV-226430r603265_rule'
  tag stig_id: 'GEN000100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36334r602714_fix'
  tag 'documentable'
  tag legacy: ['V-11940', 'SV-27051']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
