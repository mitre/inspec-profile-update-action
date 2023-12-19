control 'SV-221268' do
  title 'The application must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc "Malicious code includes viruses, worms, trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.

This requirement applies to applications providing malicious code protection. Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. Malicious code protection mechanisms (including signature definitions and rule sets) must be updated when new releases are available."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-TransportAgent "Malware Agent"

If the value of "Enabled" is set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

& env:ExchangeInstallPath\\Scripts\\Disable-Antimalwarescanning.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22983r411930_chk'
  tag severity: 'medium'
  tag gid: 'V-221268'
  tag rid: 'SV-221268r612603_rule'
  tag stig_id: 'EX16-ED-002400'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-22972r411931_fix'
  tag 'documentable'
  tag legacy: ['SV-95325', 'V-80615']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
