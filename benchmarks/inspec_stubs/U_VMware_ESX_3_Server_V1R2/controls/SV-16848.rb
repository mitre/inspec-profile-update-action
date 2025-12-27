control 'SV-16848' do
  title 'Virtual machine OS log files are not saved before rollback.'
  desc 'Traditionally, a physical server’s lifetime can be envisioned as a straight line where the current state of the machine is a static point forward as software executes, configuration changes made, and software is installed. In a virtual environment the virtual machine state is more akin to a tree, where at any point the execution can fork into N different branches. These different branches are the multiple instances of the virtual machine running or existing at any point in time.  Branches are caused by taking multiple snapshots in a continuous manner. These multiple virtual machines may be rolled back to previous states in their execution and activity that was once logged may be lost if the log files are not archived before the rollback.'
  desc 'check', 'Typically the OS log files are sent to a syslog server.  Ask the IAO/SA the location of all archived OS logs that were saved before any rollback or revert to snapshot of the virtual machine. Correlate the logs to the rollback time to ensure that they are legitimate. If no logs have been saved, this is a finding.'
  desc 'fix', 'Archive all virtual machine OS log files before any virtual machine rollback.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16266r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15906'
  tag rid: 'SV-16848r1_rule'
  tag stig_id: 'ESX1100'
  tag gtitle: 'Virtual machine OS log files are not saved'
  tag fix_id: 'F-15867r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
end
