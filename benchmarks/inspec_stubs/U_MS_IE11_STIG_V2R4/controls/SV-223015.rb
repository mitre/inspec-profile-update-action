control 'SV-223015' do
  title 'The Internet Explorer warning about certificate address mismatch must be enforced.'
  desc 'This parameter warns users if the certificate being presented by the website is invalid. Since server certificates are used to validate the identity of the web server it is critical to warn the user of a potential issue with the certificate being presented by the web server. This setting aids to prevent spoofing attacks.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page 'Turn on certificate address mismatch warning' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings Criteria: If the value "WarnOnBadCertRecving" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page 'Turn on certificate address mismatch warning' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24688r428595_chk'
  tag severity: 'medium'
  tag gid: 'V-223015'
  tag rid: 'SV-223015r879887_rule'
  tag stig_id: 'DTBI015-IE11'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24676r428596_fix'
  tag 'documentable'
  tag legacy: ['SV-59339', 'V-46475']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
