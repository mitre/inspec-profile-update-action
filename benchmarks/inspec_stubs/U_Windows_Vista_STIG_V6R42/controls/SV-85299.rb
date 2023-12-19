control 'SV-85299' do
  title 'Windows operating systems that are no longer supported by the vendor for security updates must not be installed on a system.'
  desc 'Windows operating systems that are no longer supported by Microsoft for security updates are not evaluated or updated for vulnerabilities leaving them open to potential attack. Organizations must upgrade to a supported operating system to ensure continued support.'
  desc 'check', 'Microsoft support for Windows Vista ended 11 April 2017. If Windows Vista is installed on a system, this is a finding.'
  desc 'fix', 'Upgrade Windows Vista systems to a supported operating system.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-73931r2_chk'
  tag severity: 'high'
  tag gid: 'V-4107'
  tag rid: 'SV-85299r2_rule'
  tag stig_id: 'WIN00-000001'
  tag gtitle: 'Unsupported Windows OS'
  tag fix_id: 'F-80319r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
