control 'SV-79217' do
  title 'The installed version of IE must be a supported version.'
  desc 'Unsupported versions of the operating system do not contain new security-related features and security patches that address known vulnerabilities. Software or hardware no longer supported by the manufacturer or vendor are not maintained or updated for current vulnerabilities, leaving them open to potential attack.'
  desc 'check', 'Procedure: Open Internet Explorer, Select Help, Select About.

Microsoft support for Internet Explorer 10 ended 2020 January. If Internet Explorer 10 is installed on a system, this is a finding.'
  desc 'fix', 'Upgrade Internet Explorer to a supported software version.'
  impact 0.7
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-65469r4_chk'
  tag severity: 'high'
  tag gid: 'V-64727'
  tag rid: 'SV-79217r2_rule'
  tag stig_id: 'DTBI002'
  tag gtitle: 'DTBI002-Installed version of IE is unsupported'
  tag fix_id: 'F-70657r1_fix'
  tag 'documentable'
end
