control 'SV-221216' do
  title 'The Exchange local machine policy must require signed scripts.'
  desc 'Scripts, especially those downloaded from untrusted locations, often provide a way for attackers to infiltrate a system. By setting machine policy to prevent unauthorized script executions, unanticipated system impacts can be avoided.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExecutionPolicy

If the value returned is not "RemoteSigned", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ExecutionPolicy RemoteSigned'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22931r411774_chk'
  tag severity: 'medium'
  tag gid: 'V-221216'
  tag rid: 'SV-221216r612603_rule'
  tag stig_id: 'EX16-ED-000150'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-22920r411775_fix'
  tag 'documentable'
  tag legacy: ['SV-95223', 'V-80513']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
