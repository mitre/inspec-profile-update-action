control 'SV-104293' do
  title 'Symantec ProxySG providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when access attempts to unauthorized websites and/or services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites). The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.'
  desc 'check', %q(Verify that the ProxySG is configured to generate alerts for access attempts to unauthorized websites and/or services.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, verify that each rule has a value of "Email" in the "Track" column. 
5. Right-click the "Track" field for each rule and select "Edit".
6. Click "Configure Custom Recipients Lists".
7. Click any recipient email list in the left side panel and verify that the ISSO's email address is listed in the "List Members" panel.

If Symantec ProxySG providing content filtering does not generate an alert to, at a minimum, the ISSO and ISSM when access attempts to unauthorized websites and/or services are detected, this is a finding.)
  desc 'fix', 'Configure the ProxySG to generate alerts for access attempts to unauthorized websites and/or services.

Email may be used to send alerts directly to the ISSO/ISSM. However, use caution and be selective when choosing on which Web Access rules to enable email notification.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check the "Enable Access Logging" option and click "Apply".
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, right-click the "Track" column for each rule and select "Set". Click "New," and select "Email". 
5. Select "Custom Recipients" and click "Configure Custom Recipients Lists".
6. Click "New," provide a name for the list, and enter the ISSO and ISSM email addresses in the "List Members" field.
7. Click "OK" and click "OK" again. Create message text, and click "OK".
8. Click "OK" and click "OK" again. Select File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93525r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94339'
  tag rid: 'SV-104293r1_rule'
  tag stig_id: 'SYMP-AG-000630'
  tag gtitle: 'SRG-NET-000385-ALG-000138'
  tag fix_id: 'F-100455r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
