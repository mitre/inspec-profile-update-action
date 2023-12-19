control 'SV-80441' do
  title 'Trend Deep Security must notify System Administrators and Information System Security Officers when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSOs) exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure System Administrators and Information System Security Officers are notified when accounts are modified.

1. Analyze the system using the Administration >> System Settings >> Alerts. Review the email address listed in the “Alert Event Forwarding (From The Manager).”

If this email address is not present or does not belong to a distribution for system administrators and ISSOs, this is a finding.

2. Analyze the system using the Administration >> System Settings >> System Events for “User Updated” Event ID 652.

If the options for “Record” and “Forward” are not enabled for "User Updated", this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to notify System Administrators and Information System Security Officers when accounts are modified.

1. Configure Events and Alerts to notify the SA and ISSO using the Administration > System Settings > Alerts tab. Inset a distribution email address into the “Alert Event Forwarding (From The Manager).” The distribution email address must be configured within Exchange or other email server and must associate the SA and ISSO accounts reviewing and/or managing the system.    

2. Configure the alert using the Administration > System Settings > System Events for “User Updated” Event ID 652. Select the options for Record and Forward.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65951'
  tag rid: 'SV-80441r1_rule'
  tag stig_id: 'TMDS-00-000230'
  tag gtitle: 'SRG-APP-000292'
  tag fix_id: 'F-72027r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
