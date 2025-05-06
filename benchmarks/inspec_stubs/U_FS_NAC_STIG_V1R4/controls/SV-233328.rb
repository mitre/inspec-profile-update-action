control 'SV-233328' do
  title 'Forescout must reveal error messages only to the Information System Security Officer (ISSO), Information System Security Manager (ISSM), and System Administrator (SA). This is required for compliance with C2C Step 1.'
  desc 'Ensuring the proper amount of information is provided to the Security Management staff is imperative to ensure role based access control. Only those individuals that need to know about a security error of an application need to be notified of the error.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Use the Forescout Administrator UI to verify only individuals authorized by the SSP are configured to receive error messages.

1. Log on to the Forescout UI.
2. Within the highlighted policy, under the Actions section, select a configured action to view.
3. Find the Notify section and verify that only authorized individuals (IAW the SSP) are configured for the following:
- HTTP Notification
- Send Email
- Send Notification

If Forescout error messages can be viewed by unauthorized users other than the security personnel that have a need to know, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure the individuals authorized by the SSP to receive error messages.

1. Log on to the Forescout UI.
2. Within the highlighted policy, under the Actions section, select "Add" or "Edit".
3. Find the Notify section and select from any one of the below options for notifying authorized (IAW SSP) personnel:
- HTTP Notification
- Send Email
- Send Notification'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36523r811404_chk'
  tag severity: 'medium'
  tag gid: 'V-233328'
  tag rid: 'SV-233328r811406_rule'
  tag stig_id: 'FORE-NC-000210'
  tag gtitle: 'SRG-NET-000273-NAC-000970'
  tag fix_id: 'F-36488r811405_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
