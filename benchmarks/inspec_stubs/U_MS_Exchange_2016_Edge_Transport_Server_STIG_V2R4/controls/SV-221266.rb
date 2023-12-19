control 'SV-221266' do
  title 'The application must be configured to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.'
  desc 'Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Applications providing this capability must be able to perform actions in response to detected malware. Responses include blocking, quarantining, deleting, and alerting. Other technology- or organization-specific responses may also be employed to satisfy this requirement.

Malicious code includes viruses, worms, trojan horses, and spyware. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportAgent "Malware Agent"

If the value of "Enabled" is set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

& env:ExchangeInstallPath\\Scripts\\Disable-Antimalwarescanning.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22981r411924_chk'
  tag severity: 'medium'
  tag gid: 'V-221266'
  tag rid: 'SV-221266r612603_rule'
  tag stig_id: 'EX16-ED-000750'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-22970r411925_fix'
  tag 'documentable'
  tag legacy: ['SV-95321', 'V-80611']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
