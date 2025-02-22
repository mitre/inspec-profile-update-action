control 'SV-216467' do
  title 'The operating system must employ malicious code protection mechanisms at workstations, servers, or mobile computing devices on the network to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means.'
  desc 'In order to minimize potential negative impact to the organization caused by malicious code, it is imperative that malicious code is identified and eradicated prior to entering protected enclaves via operating system entry and exit points. 

The requirement states that AV and malware protection applications must be used at entry and exit points. For the operating system, this means an anti-virus application must be installed on machines that are the entry and exit points.'
  desc 'check', 'The operator will ensure that anti-virus software is installed and operating.

If the operator is unable to provide a documented configuration for an installed anti-virus software system or if not properly used, this is a finding.'
  desc 'fix', 'The operator will ensure that anti-virus software is installed and operating.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17703r462433_chk'
  tag severity: 'medium'
  tag gid: 'V-216467'
  tag rid: 'SV-216467r603267_rule'
  tag stig_id: 'SOL-11.1-090130'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17701r462434_fix'
  tag 'documentable'
  tag legacy: ['V-47959', 'SV-60831']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
