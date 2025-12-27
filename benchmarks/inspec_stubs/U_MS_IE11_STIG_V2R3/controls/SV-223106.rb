control 'SV-223106' do
  title 'Internet Explorer Processes for MIME sniffing must be enforced (iexplore).'
  desc 'MIME sniffing is the process of examining the content of a MIME file to determine its context - whether it is a data file, an executable file, or some other type of file. This policy setting determines whether Internet Explorer MIME sniffing will prevent promotion of a file of one type to a more dangerous file type. When set to "Enabled", MIME sniffing will never promote a file of one type to a more dangerous file type. Disabling MIME sniffing configures Internet Explorer processes to allow a MIME sniff that promotes a file of one type to a more dangerous file type. For example, promoting a text file to an executable file is a dangerous promotion because any code in the supposed text file would be executed. MIME file-type spoofing is a potential threat to an organization. Ensuring these files are consistently handled helps prevent malicious file downloads from infecting the network. This guide recommends configuring this policy as "Enabled" for all environments specified in this guide. Note: This setting works in conjunction with, but does not replace, the Consistent MIME Handling settings.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING Criteria: If the value "iexplore.exe" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24779r428868_chk'
  tag severity: 'medium'
  tag gid: 'V-223106'
  tag rid: 'SV-223106r428870_rule'
  tag stig_id: 'DTBI597-IE11'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-24767r428869_fix'
  tag 'documentable'
  tag legacy: ['SV-59583', 'V-46719']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
