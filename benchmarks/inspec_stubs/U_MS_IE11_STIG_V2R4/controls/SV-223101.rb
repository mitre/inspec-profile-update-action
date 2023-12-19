control 'SV-223101' do
  title 'Internet Explorer Processes for MIME handling must be enforced. (Reserved)'
  desc 'Internet Explorer uses Multipurpose Internet Mail Extensions (MIME) data to determine file handling procedures for files received through a web server. The Consistent MIME Handling\\Internet Explorer Processes policy setting determines whether Internet Explorer requires all file-type information provided by web servers to be consistent. For example, if the MIME type of a file is text/plain but the MIME data indicates the file is really an executable file, Internet Explorer changes its extension to reflect this executable status. This capability helps ensure executable code cannot masquerade as other types of data that may be trusted. If you enable this policy setting, Internet Explorer examines all received files and enforces consistent MIME data for them. If you disable or do not configure this policy setting, Internet Explorer does not require consistent MIME data for all received files and will use the MIME data provided by the file. MIME file-type spoofing is a potential threat to an organization. Ensuring these files are consistent and properly labeled helps prevent malicious file downloads from infecting your network.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling -> 'Internet Explorer Processes' must be 'Enabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING Criteria: If the value "(Reserved)" is REG_SZ = 1, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling -> 'Internet Explorer Processes' to 'Enabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24774r428853_chk'
  tag severity: 'medium'
  tag gid: 'V-223101'
  tag rid: 'SV-223101r879627_rule'
  tag stig_id: 'DTBI590-IE11'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-24762r428854_fix'
  tag 'documentable'
  tag legacy: ['SV-59573', 'V-46709']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
