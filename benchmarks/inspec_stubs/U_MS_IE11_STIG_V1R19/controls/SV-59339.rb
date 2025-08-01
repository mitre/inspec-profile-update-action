control 'SV-59339' do
  title 'The Internet Explorer warning about certificate address mismatch must be enforced.'
  desc 'This parameter warns users if the certificate being presented by the website is invalid. Since server certificates are used to validate the identity of the web server it is critical to warn the user of a potential issue with the certificate being presented by the web server. This setting aids to prevent spoofing attacks.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page 'Turn on certificate address mismatch warning' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "WarnOnBadCertRecving" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page 'Turn on certificate address mismatch warning' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-49685r2_chk'
  tag severity: 'medium'
  tag gid: 'V-46475'
  tag rid: 'SV-59339r1_rule'
  tag stig_id: 'DTBI015-IE11'
  tag gtitle: 'DTBI015-IE11-Warning of certificate mismatch'
  tag fix_id: 'F-50265r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001274']
  tag nist: ['SI-4 (12)']
end
