control 'SV-221269' do
  title 'The application must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc "Malicious code includes viruses, worms, trojan horses, and spyware. The code provides the ability for a malicious user to read from and write to files and folders on a computer's hard drive. Malicious code may also be able to run and attach programs, which may allow the unauthorized distribution of malicious mobile code. Once this code is installed on endpoints within the network, unauthorized users may be able to breach firewalls and gain access to sensitive data.

This requirement applies to applications providing malicious code protection. Malicious code protection mechanisms include, but are not limited, to, anti-virus and malware detection software. Malicious code protection mechanisms (including signature definitions and rule sets) must be updated when new releases are available."
  desc 'check', 'Site must utilize an approved DoD third-party malicious code scanner.

Consult with System Administrator to demonstrate the application being used to provide malicious code protection in the Exchange implementation.

If System Administrator is unable to demonstrate a third-party malicious code protection application, this is a finding.

If System Administrator is unaware of a third-party malicious code protection application, this is a finding.'
  desc 'fix', 'Following vendor best practice guidance, install and configure a third-party malicious code protection application.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22984r411933_chk'
  tag severity: 'medium'
  tag gid: 'V-221269'
  tag rid: 'SV-221269r612603_rule'
  tag stig_id: 'EX16-ED-002410'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-22973r411934_fix'
  tag 'documentable'
  tag legacy: ['SV-95327', 'V-80617']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
