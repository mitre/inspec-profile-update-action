control 'SV-221267' do
  title 'The application must be configured to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.'
  desc 'Malicious code protection mechanisms include, but are not limited, to anti-virus and malware detection software. In order to minimize potential negative impact to the organization that can be caused by malicious code, it is imperative that malicious code is identified and eradicated. 

Applications providing this capability must be able to perform actions in response to detected malware. Responses include blocking, quarantining, deleting, and alerting. Other technology- or organization-specific responses may also be employed to satisfy this requirement.

Malicious code includes viruses, worms, trojan horses, and spyware. 

This requirement applies to applications providing malicious code protection.'
  desc 'check', 'Site must utilize an approved DoD third-party malicious code scanner.

Consult with System Administrator to demonstrate the application being used to provide malicious code protection in the Exchange implementation.

If System Administrator is unable to demonstrate a third-party malicious code protection application, this is a finding.

If System Administrator is unaware of a third-party malicious code protection application, this is a finding.'
  desc 'fix', 'Following vendor best practice guidance, install and configure a third-party malicious code protection application.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22982r411927_chk'
  tag severity: 'medium'
  tag gid: 'V-221267'
  tag rid: 'SV-221267r612603_rule'
  tag stig_id: 'EX16-ED-000760'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-22971r411928_fix'
  tag 'documentable'
  tag legacy: ['SV-95323', 'V-80613']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
