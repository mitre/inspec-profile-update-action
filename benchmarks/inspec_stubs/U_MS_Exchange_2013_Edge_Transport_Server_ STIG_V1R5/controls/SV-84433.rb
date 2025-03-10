control 'SV-84433' do
  title 'The Exchange local machine policy must require signed scripts.'
  desc 'Scripts, especially those downloaded from untrusted locations, often provide a way for attackers to infiltrate a system. By setting machine policy to prevent unauthorized script executions, unanticipated system impacts can be avoided.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExecutionPolicy

If the value returned is not RemoteSigned, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ExecutionPolicy RemoteSigned'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69811'
  tag rid: 'SV-84433r1_rule'
  tag stig_id: 'EX13-EG-000075'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-76023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
