control 'SV-108119' do
  title 'The installed version of IIS must be a supported version.'
  desc 'Unsupported versions of the operating system do not contain new security-related features and security patches that address known vulnerabilities. Software or hardware no longer supported by the manufacturer or vendor are not maintained or updated for current vulnerabilities, leaving them open to potential attack.'
  desc 'check', 'Procedure: Open IIS Manager, Select Help, Select About IIS.

Microsoft support for Internet Information Services (IIS) 7 ended 2020 January. If IIS 7 is installed on a system, this is a finding.'
  desc 'fix', 'Upgrade IIS to a supported software version.'
  impact 0.7
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-97855r1_chk'
  tag severity: 'high'
  tag gid: 'V-99015'
  tag rid: 'SV-108119r1_rule'
  tag stig_id: 'WG500'
  tag gtitle: 'WG500-Installed version of IIS is unsupported.'
  tag fix_id: 'F-104691r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
