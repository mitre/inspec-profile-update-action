control 'SV-44052' do
  title 'Local machine policy must require signed scripts.'
  desc 'Scripts often provide a way for attackers to infiltrate a system, especially those downloaded from untrusted locations.   By setting machine policy to prevent unauthorized script executions, unanticipated system impacts can be avoided.  Failure to allow only signed remote scripts reduces the attack vector vulnerabilities from unsigned remote scripts.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ExecutionPolicy

If the value of 'LocalMachine' does not return a value of 'RemoteSigned', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-ExecutionPolicy RemoteSigned'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33632'
  tag rid: 'SV-44052r1_rule'
  tag stig_id: 'Exch-2-019'
  tag gtitle: 'Exch-2-019'
  tag fix_id: 'F-37524r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
