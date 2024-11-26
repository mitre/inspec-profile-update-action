control 'SV-223307' do
  title 'The Save from URL feature must be enabled in all Office programs.'
  desc 'Typically, when Internet Explorer loads a web page from a Universal Naming Convention (UNC) share that contains a Mark of the Web (MOTW) comment, indicating the page was saved from a site on the Internet, Internet Explorer runs the page in the Internet security zone instead of the less restrictive Local Intranet security zone. This functionality can be controlled separately for instances of Internet Explorer spawned by Office applications (for example, if a user clicks a link in an Office document or selects a menu option that loads a web page). If Internet Explorer does not evaluate the page for a MOTW, potentially dangerous code could be allowed to run.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Saved from URL is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_unc_saved

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Saved from URL to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24980r442140_chk'
  tag severity: 'medium'
  tag gid: 'V-223307'
  tag rid: 'SV-223307r508019_rule'
  tag stig_id: 'O365-CO-000025'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24968r442141_fix'
  tag 'documentable'
  tag legacy: ['SV-108793', 'V-99689']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
