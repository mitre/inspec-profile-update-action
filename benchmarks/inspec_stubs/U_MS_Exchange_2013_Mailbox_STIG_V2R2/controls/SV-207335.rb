control 'SV-207335' do
  title 'The applications built-in Malware Agent must be disabled.'
  desc "Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, Trojan horses, and Spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

Exchange's built-in Malware Agent is not designed to address all malicious code protection workloads. This workload is best handled by third-party anti-virus and intrusion prevention software.

Site must utilize an approved DoD scanner. Exchange Malware software has a limited scanning capability and does not scan files that are downloaded, opened, or executed."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportAgent "Malware Agent"

If the value of Enabled is set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

& env:ExchangeInstallPath\\Scripts\\Disable-Antimalwarescanning.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7593r393518_chk'
  tag severity: 'medium'
  tag gid: 'V-207335'
  tag rid: 'SV-207335r615936_rule'
  tag stig_id: 'EX13-MB-003030'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-7593r393519_fix'
  tag 'documentable'
  tag legacy: ['SV-84677', 'V-70055']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
