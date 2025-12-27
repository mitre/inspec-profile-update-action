control 'SV-223102' do
  title 'Internet Explorer Processes for MIME handling must be enforced (Explorer).'
  desc 'Internet Explorer uses Multipurpose Internet Mail Extensions (MIME) data to determine file handling procedures for files received through a web server. The Consistent MIME Handling\\Internet Explorer Processes policy setting determines whether Internet Explorer requires all file-type information provided by web servers to be consistent. For example, if the MIME type of a file is text/plain but the MIME data indicates the file is really an executable file, Internet Explorer changes its extension to reflect this executable status. This capability helps ensure executable code cannot masquerade as other types of data that may be trusted. If you enable this policy setting, Internet Explorer examines all received files and enforces consistent MIME data for them. If you disable or do not configure this policy setting, Internet Explorer does not require consistent MIME data for all received files and will use the MIME data provided by the file. MIME file-type spoofing is a potential threat to the organization. Ensuring these files are consistent and properly labeled helps prevent malicious file downloads from infecting the network. This guide recommends configuring this policy as "Enabled" for all environments specified in this guide.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING Criteria: If the value "explorer.exe" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24775r428856_chk'
  tag severity: 'medium'
  tag gid: 'V-223102'
  tag rid: 'SV-223102r879627_rule'
  tag stig_id: 'DTBI592-IE11'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-24763r428857_fix'
  tag 'documentable'
  tag legacy: ['SV-59575', 'V-46711']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
