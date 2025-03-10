control 'SV-33918' do
  title 'Saved from URL mark to assure Internet zone processing must be enforced.'
  desc 'Typically, when Internet Explorer loads a Web page from a Universal Naming Convention (UNC) share that contains a Mark of the Web (MOTW) comment, indicating the page was saved from a site on the Internet, Internet Explorer runs the page in the Internet security zone instead of the less restrictive Local Intranet security zone. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). If Internet Explorer does not evaluate the page for a MOTW, potentially dangerous code could be allowed to run.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Saved from URL” must be “Enabled” and a check in the ‘winproj.exe’ check box must be present.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_UNC_SAVEDFILECHECK

Criteria: If the value winproj.exe is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Saved from URL” to “Enabled” and place a check in the ‘winproj.exe’ check box.'
  impact 0.5
  ref 'DPMS Target Microsoft Project 2010'
  tag check_id: 'C-34343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17175'
  tag rid: 'SV-33918r1_rule'
  tag stig_id: 'DTOO117 - Project'
  tag gtitle: 'DTOO117 - Saved from URL'
  tag fix_id: 'F-29991r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
