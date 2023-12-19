control 'SV-16821' do
  title 'VirtualCenter does not log user, group, permission or role changes.'
  desc 'VirtualCenter Servers not configured to log user, group, permission and role changes will not have the ability to review past system and user events.  Recording these events is critical to establishing a recorded history of system events, enabling system administrators to diagnose intermittent system problems, suspicious user activity, and assisting with investigations. Log events also verify that the established policies configured on the system are in fact working as configured.'
  desc 'check', '1. Log into VirtualCenter with the VI Client.
2. Select the Administration Menu at the top of the page.
3. Select VirtualCenter Management Server Configuration.
4. Select Logging Options.
5. Verify that VirtualCenter Logging is configured to Info(Normal Logging) or higher (Verbose or Trivia)'
  desc 'fix', 'Configure VirtualCenter Logging to Info or higher.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15880'
  tag rid: 'SV-16821r1_rule'
  tag stig_id: 'ESX0810'
  tag gtitle: 'VirtualCenter does not log changes'
  tag fix_id: 'F-15840r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
