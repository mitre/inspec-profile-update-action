control 'SV-104299' do
  title 'Symantec ProxySG providing content filtering must send an alert to, at a minimum, the ISSO and ISSM when detection events occur.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel."
  desc 'check', %q(Verify that the ProxySG is configured to generate alerts for access attempts to unauthorized websites and/or services.

1. Log on to the Web Management console.
2. Browse to "Configuration" and click "Access Logging. Verify that "Enable Access Logging" is checked.
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, verify that each rule has a value of "Email" in the "Track" column. 
5. Right-click the "Track" field for each rule and select "Edit".
6. Click "Configure Custom Recipients Lists".
7. Click any recipient email list in the left side panel and verify that the ISSO's email address is listed in the "List Members" panel.

If Symantec ProxySG providing content filtering does not send an alert to, at a minimum, the ISSO and ISSM when detection events occur, this is a finding.)
  desc 'fix', 'Configure the ProxySG to generate alerts for access attempts to unauthorized websites and/or services.

Email may be used to send alerts directly to the ISSO/ISSM. However, use caution and be selective when choosing which Web Access rules on which to enable email notification.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check the "Enable Access Logging" option and click "Apply".
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, right-click the "Track" column for each rule and select "Set". Click "New" and select "Email". 
5. Select "Custom Recipients" and click "Configure Custom Recipients Lists".
6. Click "New," provide a name for the list, and enter the ISSO and ISSM email addresses in the "List Members" field.
7. Click "OK" and click "OK" again. Create message text and click "OK".
8. Click "OK" and click "OK" again. Select File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93531r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94345'
  tag rid: 'SV-104299r1_rule'
  tag stig_id: 'SYMP-AG-000660'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-100461r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
