control 'SV-16822' do
  title 'VirtualCenter logs are reviewed daily.'
  desc 'It is necessary to review VirtualCenter logs for suspicious activity, problems, attacks, or system warnings will go undetected.  These logs provide visibility into the activities and events of the VirtualCenter.  These logs enable system administrators and auditors the ability to recreate past events, monitor the system, and ensure security policies are being enforced.'
  desc 'check', 'Ask the IAO/SA how often they review the VirtualCenter logs. VirtualCenter logs include System Logs and Events. If the logs are not reviewed daily, this is a finding.'
  desc 'fix', 'Review the VirtualCenter logs daily.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16240r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15881'
  tag rid: 'SV-16822r1_rule'
  tag stig_id: 'ESX0820'
  tag gtitle: 'VirtualCenter logs are reviewed daily'
  tag fix_id: 'F-15841r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
