control 'SV-224371' do
  title 'The BlackBerry UEM server must [selection: invoke platform-provided functionality, implement functionality] to generate an audit record of the following auditable events: c. [selection: Commands issued to the MDM Agent].'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, administrators must have the ability to view them.

SFR ID: FAU_GEN.1.1(1)'
  desc 'check', 'Review the audit record which can be found in the UEM console in Settings >> Infrastructure >> Audit settings >> Security event audit settings section.

Verify both "Command" events are listed and "setting" is set to "All" for the "Command delivered" event.
If both "Command" events are not listed and "setting" is not set to "All" for the "Command delivered" event, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM, do the following:
1. On the menu bar, click Settings >> Infrastructure >> Audit settings.
2. In the right pane, click the edit icon.
3. To add security events to audit, click + . Select the events and click Add.
4. Select each "Command" event (Command delivered, Command sent).
5. In the Setting column, select "all" for the "Command delivered" event. 
6. Click Save.
Note: For audit record fields for server audits, include: Commands sent to the device.'
  impact 0.3
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26048r588324_chk'
  tag severity: 'low'
  tag gid: 'V-224371'
  tag rid: 'SV-224371r604136_rule'
  tag stig_id: 'BUEM-00-000010'
  tag gtitle: 'PP-MDM-412000'
  tag fix_id: 'F-26036r588326_fix'
  tag 'documentable'
  tag legacy: ['V-102897', 'SV-111859']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
