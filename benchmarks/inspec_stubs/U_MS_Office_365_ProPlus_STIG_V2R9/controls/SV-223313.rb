control 'SV-223313' do
  title 'Dynamic Data Exchange (DDE) server lookup in Excel must be blocked.'
  desc 'This policy setting allows you to control whether Dynamic Data Exchange (DDE) server lookup is allowed.

By default, DDE server lookup is turned on, but users can turn off DDE server lookup by going to File >> Options >> Trust Center >> Trust Center Settings >> External Content.

If you enable this policy setting, DDE server lookup is not allowed, and users cannot turn on DDE server lookup in the Trust Center.

Note: If you are using Dynamic Data Exchange (DDE) server launch, which is not recommended, do not enable this policy setting, because DDE server launch requires DDE server lookup to be on.

If you disable or do not configure this policy setting, DDE server lookup is turned on, but users can turn off DDE server lookup in the Trust Center.

Note: This policy setting only applies to subscription versions of Office, such as Office 365 ProPlus.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Don't allow Dynamic Data Exchange (DDE) server lookup in Excel is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\software\policies\microsoft\office\16.0\excel\security\external content

If the value for "disableddeserverlookup" is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> External Content >> Don't allow Dynamic Data Exchange (DDE) server lookup in Excel to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24986r442158_chk'
  tag severity: 'medium'
  tag gid: 'V-223313'
  tag rid: 'SV-223313r879628_rule'
  tag stig_id: 'O365-EX-000004'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24974r442159_fix'
  tag 'documentable'
  tag legacy: ['SV-108805', 'V-99701']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
