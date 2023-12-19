control 'SV-221265' do
  title 'The application must configure malicious code protection mechanisms to perform periodic scans of the information system every seven days.'
  desc 'Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Malicious code includes viruses, worms, trojan horses, and spyware. It is not enough to simply have the software installed; this software must periodically scan the system to search for malware on an organization-defined frequency. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Site must utilize an approved DoD third-party malicious code scanner.

Consult with System Administrator to demonstrate the application being used to provide malicious code protection in the Exchange implementation.

If System Administrator is unable to demonstrate a third-party malicious code protection application, this is a finding.

If System Administrator is unaware of a third-party malicious code protection application, this is a finding.'
  desc 'fix', 'Following vendor best practice guidance, install and configure a third-party malicious code protection application.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22980r411921_chk'
  tag severity: 'medium'
  tag gid: 'V-221265'
  tag rid: 'SV-221265r612603_rule'
  tag stig_id: 'EX16-ED-000730'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-22969r411922_fix'
  tag 'documentable'
  tag legacy: ['SV-95319', 'V-80609']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
