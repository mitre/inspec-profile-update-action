control 'SV-84373' do
  title 'Exchange Local machine policy must require signed scripts.'
  desc 'Scripts often provide a way for attackers to infiltrate a system, especially those downloaded from untrusted locations. By setting machine policy to prevent unauthorized script executions, unanticipated system impacts can be avoided. Failure to allow only signed remote scripts reduces the attack vector vulnerabilities from unsigned remote scripts.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExecutionPolicy

If the value returned is not RemoteSigned, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ExecutionPolicy RemoteSigned'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69751'
  tag rid: 'SV-84373r1_rule'
  tag stig_id: 'EX13-CA-000090'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-75957r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
