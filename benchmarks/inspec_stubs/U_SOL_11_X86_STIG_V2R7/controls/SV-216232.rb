control 'SV-216232' do
  title 'The operating system must have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means.'
  desc 'This requirement applies to email servers only. 

In order to minimize potential negative impact to the organization caused by malicious code, it is imperative that malicious code is identified and eradicated prior to entering protected enclaves via operating system entry and exit points. 

The requirement states that AV and malware protection applications must be used at entry and exit points. For the operating system, this means an anti-virus application must be installed on machines that are the entry and exit points.'
  desc 'check', 'The operator will ensure that anti-virus software is installed and operating.

If the operator is unable to provide a documented configuration for an installed anti-virus software system or if not properly used, this is a finding.'
  desc 'fix', 'The operator will ensure that anti-virus software is installed and operating.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17470r373075_chk'
  tag severity: 'medium'
  tag gid: 'V-216232'
  tag rid: 'SV-216232r603268_rule'
  tag stig_id: 'SOL-11.1-090140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17468r373076_fix'
  tag 'documentable'
  tag legacy: ['V-47955', 'SV-60827']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
