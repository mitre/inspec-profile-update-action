control 'SV-82647' do
  title 'The Mainframe Product must notify system programmers and security administrators of account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator (SA) and information system security officer (ISSO) is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If the Mainframe Product does not notify system programmers and security administrators of account enabling actions, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to notify system programmers and security administrators of account enabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68715r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68157'
  tag rid: 'SV-82647r2_rule'
  tag stig_id: 'SRG-APP-000320-MFP-000048'
  tag gtitle: 'SRG-APP-000320-MFP-000048'
  tag fix_id: 'F-74273r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
