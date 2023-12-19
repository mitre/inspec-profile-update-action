control 'SV-216442' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered supported if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Determine the operating system version.

# uname -a

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17678r371414_chk'
  tag severity: 'high'
  tag gid: 'V-216442'
  tag rid: 'SV-216442r603267_rule'
  tag stig_id: 'SOL-11.1-080010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17676r371415_fix'
  tag 'documentable'
  tag legacy: ['V-48027', 'SV-60899']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
