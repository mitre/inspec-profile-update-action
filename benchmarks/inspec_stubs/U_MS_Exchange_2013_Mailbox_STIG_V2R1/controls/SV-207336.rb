control 'SV-207336' do
  title 'A DoD-approved third party Exchange-aware malicious code protection application must be implemented.'
  desc "Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, Trojan horses, and Spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

Exchange's built-in Malware Agent is not designed to address all malicious code protection workloads. This workload is best handled by third-party anti-virus and intrusion prevention software.

Site must utilize an approved DoD scanner. Exchange Malware software has a limited scanning capability and does not scan files that are downloaded, opened, or executed."
  desc 'check', 'Site must utilize an approved DoD third party malicious code scanner.

Consult with System Administrator to demonstrate the application being used to provide malicious code protection in the Exchange implementation.

If System Administrator is unable to demonstrate a third party malicious code protection application, this is a finding.

If System Administrator is unaware of a third party malicious code protection application, this is a finding.'
  desc 'fix', 'Following vendor best practice guidance, install and configure the third party malicious code protection application.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7594r393521_chk'
  tag severity: 'medium'
  tag gid: 'V-207336'
  tag rid: 'SV-207336r615936_rule'
  tag stig_id: 'EX13-MB-003031'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-7594r393522_fix'
  tag 'documentable'
  tag legacy: ['SV-84675', 'V-70053']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
