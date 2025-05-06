control 'SV-54002' do
  title 'Trusted add-ins behavior for email must be configured.'
  desc 'The Outlook object model includes entry points to access Outlook data, save data to specified locations, and send email messages, all of which can be used by malicious application developers. To help protect these entry points, the Object Model Guard warns users and prompts them for confirmation when untrusted code, including add-ins, attempts to use the object model to obtain email address information, store data outside of Outlook, execute certain actions, and send email messages. 
To reduce excessive security warnings when add-ins are used, administrators can specify a list of trusted add-ins that can access the Outlook object model silently, without raising prompts. This trusted add-in list should be treated with care, because a malicious add-in could access and forward sensitive information if added to the list.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Programmatic Security -> Trusted Add-ins "Configure trusted add-ins" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Outlook\\security\\trustedaddins

In some reported configurations, the registry key remains after disabling the setting but the value is empty.

If the registry key exists, with entries, this is a finding.
If the registry key exists, but with no entries, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Programmatic Security -> Trusted Add-ins "Configure trusted add-ins" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47972r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17575'
  tag rid: 'SV-54002r2_rule'
  tag stig_id: 'DTOO256'
  tag gtitle: 'DTOO256 - Trusted Add-Ins Security'
  tag fix_id: 'F-46891r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
