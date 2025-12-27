control 'SV-45417' do
  title 'The Internet Explorer warning about certificate address mismatch must be enforced.'
  desc 'This parameter warns users if the certificate being presented by the website is invalid. Since server certificates are used to validate the identity of the web server it is critical to warn the user of a potential issue with the certificate being presented by the web server. This setting aids to prevent spoofing attacks.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page "Turn on certificate address mismatch warning" must be "Enabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings 

Criteria: If the value WarnOnBadCertRecving is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page "Turn on certificate address mismatch warning" to "Enabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42768r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6239'
  tag rid: 'SV-45417r1_rule'
  tag stig_id: 'DTBI015'
  tag gtitle: 'DTBI015-IE Warning of invalid certificates'
  tag fix_id: 'F-38815r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
