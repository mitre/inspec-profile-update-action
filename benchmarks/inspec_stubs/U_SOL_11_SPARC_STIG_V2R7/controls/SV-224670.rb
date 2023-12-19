control 'SV-224670' do
  title 'The operating system must prevent non-privileged users from circumventing malicious code protection capabilities.'
  desc 'In order to minimize potential negative impact to the organization caused by malicious code, it is imperative that malicious code is identified and eradicated prior to entering protected enclaves via operating system entry and exit points. 

The requirement states that AV and malware protection applications must be used at entry and exit points. For the operating system, this means an anti-virus application must be installed on machines that are the entry and exit points.'
  desc 'check', 'The operator will ensure that anti-virus software is installed and operating.

If the operator is unable to provide a documented configuration for an installed anti-virus software system or if not properly used, this is a finding.'
  desc 'fix', 'The operator will ensure that anti-virus software is installed and operating.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-26359r462436_chk'
  tag severity: 'medium'
  tag gid: 'V-224670'
  tag rid: 'SV-224670r854547_rule'
  tag stig_id: 'SOL-11.1-090120'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-26347r462437_fix'
  tag 'documentable'
  tag legacy: ['V-47963', 'SV-60835']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
