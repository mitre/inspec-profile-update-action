control 'SV-80443' do
  title 'Trend Deep Security must notify System Administrators and Information System Security Officers for account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual application users or for identifying the application processes themselves. 

In order to detect and respond to events that affect user accessibility and application processing, applications must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure System Administrators and Information System Security Officers are notified when accounts are disabled.

1. Analyze the system using the Administration >> System Settings >> Alerts. Review the email address listed in the “Alert Event Forwarding (From The Manager).”

If this email address is not present or does not belong to a distribution for system administrators and ISSOs, this is a finding.

2. Analyze the system using the Administration >> System Settings >> System Events for “User Locked Out” Event ID 603.

If the options for “Record” and “Forward” are not enabled for "User Locked Out", this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to notify System Administrators and Information System Security Officers for account disabling actions.

1. Configure Events and Alerts to notify the SA and ISSO using the Administration >> System Settings >> Alerts tab. Inset a distribution email address into the “Alert Event Forwarding (From The Manager).” The distribution email address must be configured within Exchange or other email server and must associate the SA and ISSO accounts reviewing and/or managing the system.

2. Configure the alert using the Administration >> System Settings >> System Events for “User Locked Out” Event ID 603. Select the options for “Record” and “Forward”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65953'
  tag rid: 'SV-80443r1_rule'
  tag stig_id: 'TMDS-00-000235'
  tag gtitle: 'SRG-APP-000293'
  tag fix_id: 'F-72029r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
