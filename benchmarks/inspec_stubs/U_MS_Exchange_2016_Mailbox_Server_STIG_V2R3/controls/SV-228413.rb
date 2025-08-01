control 'SV-228413' do
  title 'The applications built-in Malware Agent must be disabled.'
  desc "Malicious code protection mechanisms include but are not limited to anti-virus and malware detection software. To minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, trojan horses, and spyware. It is not enough to have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

Exchange's built-in Malware Agent is not designed to address all malicious code protection workloads. This workload is best handled by third-party anti-virus and intrusion prevention software.

Sites must use an approved DoD scanner. Exchange Malware software has a limited scanning capability and does not scan files that are downloaded, opened, or executed."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportAgent "Malware Agent"

If the value of "Enabled" is set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

& env:ExchangeInstallPath\\Scripts\\Disable-Antimalwarescanning.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30646r497035_chk'
  tag severity: 'medium'
  tag gid: 'V-228413'
  tag rid: 'SV-228413r612748_rule'
  tag stig_id: 'EX16-MB-002880'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-30631r497036_fix'
  tag 'documentable'
  tag legacy: ['SV-95437', 'V-80727']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
