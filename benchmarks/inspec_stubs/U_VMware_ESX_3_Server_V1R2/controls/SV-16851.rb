control 'SV-16851' do
  title 'Virtual machine log files are not maintained for 1 year.'
  desc 'Storing log files for at least a year provides a way to recover these files in case an investigation is necessary. Typically these files are stored offline on tape media or external networks. Log files enable the enforcement of individual accountability by creating a reconstruction of events.  They also assist in problem identification that may lead to problem resolution.  If these log files are not retained, there is no way to trace or reconstruct the events, and if it was discovered the network was hacked, there would be no way to trace the full extent of the compromise.'
  desc 'check', 'Locate where archived virtual machine log files (vmware.log) are stored. If they are offsite, review the process to move them to this alternative site. Verify that the log files are retained for at least one year at a minimum.  This can be verified by reviewing the dates of the oldest backup files or media. If the log files are not stored for a minimum of one year, this is a finding.'
  desc 'fix', 'Retain virtual machine log files for a minimum of one year.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16272r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15909'
  tag rid: 'SV-16851r1_rule'
  tag stig_id: 'ESX1130'
  tag gtitle: 'Virtual machine log files are not kept for 1 yr'
  tag fix_id: 'F-15870r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
