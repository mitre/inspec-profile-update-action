control 'SV-33596' do
  title 'Trusted add-ins behavior for eMail must be configured.'
  desc 'The Outlook object model includes entry points to access Outlook data, save data to specified locations, and send e-mail messages, all of which can be used by malicious application developers. To help protect these entry points, the Object Model Guard warns users and prompts them for confirmation when untrusted code, including add-ins, attempts to use the object model to obtain e-mail address information, store data outside of Outlook, execute certain actions, and send e-mail messages. 
To reduce excessive security warnings when add-ins are used, administrators can specify a list of trusted add-ins that can access the Outlook object model silently, without raising prompts. This trusted add-in list should be treated with care, because a malicious add-in could access and forward sensitive information if added to the list.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Programmatic Security -> Trusted Add-ins “Configure trusted add-ins” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\Outlook\\security\\trustedaddins

Criteria: If the registry key exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Programmatic Security -> Trusted Add-ins “Configure trusted add-ins” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34058r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17575'
  tag rid: 'SV-33596r1_rule'
  tag stig_id: 'DTOO256 - Outlook'
  tag gtitle: 'DTOO256 - Trusted Add-Ins Security'
  tag fix_id: 'F-29738r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
