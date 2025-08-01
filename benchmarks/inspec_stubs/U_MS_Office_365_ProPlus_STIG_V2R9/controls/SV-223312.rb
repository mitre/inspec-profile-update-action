control 'SV-223312' do
  title 'Dynamic Data Exchange (DDE) server launch in Excel must be blocked.'
  desc "This policy setting allows you to control whether Dynamic Data Exchange (DDE) server launch is allowed.

By default, DDE server launch is turned off, but users can turn on DDE server launch by going to File >> Options >> Trust Center >> Trust Center Settings >> External Content.

For security reasons, turning on DDE server launch is not recommended.

Note: For DDE server launch to work, Dynamic Data Exchange (DDE) server lookup must be turned on. Be sure that the “Don't allow Dynamic Data Exchange (DDE) server lookup” policy setting is not enabled, because enabling that policy setting turns off DDE server lookup.

If you enable this policy setting, DDE server launch is not allowed, and users cannot turn on DDE server launch in the Trust Center.

If you disable this policy setting, DDE server launch is allowed, and users cannot turn off DDE server launch in the Trust Center. For security reasons, this is not recommended.

If you do not configure this policy setting, DDE server launch is turned off, but users can turn on DDE server launch in the Trust Center.

Note: This policy setting only applies to subscription versions of Office, such as Office 365 ProPlus."
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Don't allow Dynamic Data Exchange (DDE) server launch in Excel is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\software\policies\microsoft\office\16.0\excel\security\external content

If the value for "disableddeserverlaunch" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Don't allow Dynamic Data Exchange (DDE) server launch in Excel to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24985r442155_chk'
  tag severity: 'medium'
  tag gid: 'V-223312'
  tag rid: 'SV-223312r879628_rule'
  tag stig_id: 'O365-EX-000003'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24973r442156_fix'
  tag 'documentable'
  tag legacy: ['SV-108803', 'V-99699']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
