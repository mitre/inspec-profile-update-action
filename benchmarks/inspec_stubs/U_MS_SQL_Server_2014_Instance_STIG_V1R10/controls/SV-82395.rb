control 'SV-82395' do
  title 'SQL Server must disable communication protocols not required for operation.'
  desc 'Having unnecessary protocols enabled exposes the system to avoidable threats.  In a typical installation, only TCP/IP will be required.'
  desc 'check', 'Review the system security plan to determine the communication protocols used by the SQL Server instance.

Open SQL Server Configuration Manager from the Windows Start menu or by entering "SQLServerManager12.msc" in a Command Prompt window or in the Run dialog box.  Select SQL Server Network Configuration >> Protocols for <instance name>.  Review the list of protocols.

If any that are not required are shown as enabled, this is a finding.'
  desc 'fix', 'In SQL Server Configuration Manager, right-click on each enabled protocol that is not required.  Select Disabled.

Close SQL Server Configuration Manager.  Restart SQL Server.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68475r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67905'
  tag rid: 'SV-82395r1_rule'
  tag stig_id: 'SQL4-00-034200'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-74021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
