control 'SV-33417' do
  title 'Saved from URL mark to assure Internet zone processing must be enforced.'
  desc 'Typically, when Internet Explorer loads a Web page from a Universal Naming Convention (UNC) share that contains a Mark of the Web (MOTW) comment, indicating the page was saved from a site on the Internet, Internet Explorer runs the page in the Internet security zone instead of the less restrictive Local Intranet security zone. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a Web page). If Internet Explorer does not evaluate the page for a MOTW, potentially dangerous code could be allowed to run.'
  desc 'check', "The policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Saved from URL” must be “Enabled” and a check in the ‘powerpnt.exe’ and 'pptview.exe' check boxes must be present. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_UNC_SAVEDFILECHECK

Criteria: If the value powerpnt.exe is REG_DWORD = 1, this is not a finding.

AND

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_UNC_SAVEDFILECHECK

Criteria: If the value pptview.exe is REG_DWORD = 1, this is not a finding."
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2010 (Machine) -> Security Settings -> IE Security “Saved from URL” to “Enabled” and place a check in the ‘powerpnt.exe’ and 'pptview.exe' check boxes."
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-33900r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17175'
  tag rid: 'SV-33417r1_rule'
  tag stig_id: 'DTOO117 - PowerPoint'
  tag gtitle: 'DTOO117 - Saved from URL'
  tag fix_id: 'F-29589r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
