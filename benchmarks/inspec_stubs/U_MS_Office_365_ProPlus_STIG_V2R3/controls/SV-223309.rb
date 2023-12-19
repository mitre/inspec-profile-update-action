control 'SV-223309' do
  title 'Flash player activation must be disabled in all Office programs.'
  desc %q(This policy setting controls whether the Adobe Flash control can be activated by Office documents. Note that activation blocking applies only within Office processes.

If you enable this policy setting, you can choose from three options to control whether and how Flash is blocked from activation:

1. "Block all activation" prevents the Flash control from being loaded, whether directly referenced by the document or indirectly by another embedded object.
2. "Block embedding/linking, allow other activation" prevents the Flash control from being loaded when directly referenced by the document, but does not prevent activation through another object.
3. "Allow all activation" restores Office's default behavior, allowing the Flash control to be activated.

Because this setting is not a true Group Policy setting and "tattoos" the registry, enabling the "Allow all activation" option is the only way to restore default behavior after either of the "Block" options has been applied. It is not recommended to configure this setting to "Disabled" or "Not Configured" after it has been enabled.)
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> Block Flash activation in Office documents >> Enabled >> Block all activation is set to "Enabled" Block all activation.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\SOFTWARE\\Microsoft\\Office\\Common\\COM Compatibility

If the value for COMMENT is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> Block Flash activation in Office documents >> Enabled >> Block all activation to "Enabled" (Block all activation).'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24982r442146_chk'
  tag severity: 'medium'
  tag gid: 'V-223309'
  tag rid: 'SV-223309r508019_rule'
  tag stig_id: 'O365-CO-000027'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-24970r442147_fix'
  tag 'documentable'
  tag legacy: ['SV-108797', 'V-99693']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
