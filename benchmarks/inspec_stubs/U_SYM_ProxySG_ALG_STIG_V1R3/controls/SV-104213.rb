control 'SV-104213' do
  title 'Symantec ProxySG must be configured to send the access logs to the centralized log server continuously.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Off-loading is a common process in information systems with limited audit storage capacity. The audit storage on the ALG is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time, which indicates that the time from event detection to off-loading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify that continuous audit log off-loading is configured.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Access Logging >> Logs.
3. Click "Upload Client" and Verify that a "Client type" is specified. 
4.  Click the "Upload Schedule" and Verify that "Upload the access log continuously" is selected.

If Symantec ProxySG is not configured to send the access logs to the centralized log server continuously, this is a finding.'
  desc 'fix', 'Configure continuous audit log off-loading.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Access Logging >> Logs.
3. Click "Upload Schedule" and select "Upload the access log continuously" option.
4. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93445r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94259'
  tag rid: 'SV-104213r1_rule'
  tag stig_id: 'SYMP-AG-000220'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-100375r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
