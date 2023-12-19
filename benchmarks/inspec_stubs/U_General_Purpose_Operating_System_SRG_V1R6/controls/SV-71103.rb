control 'SV-71103' do
  title 'The operating system must isolate security functions from nonsecurity functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify the operating system isolates security functions from nonsecurity functions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to isolate security functions from nonsecurity functions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57411r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56843'
  tag rid: 'SV-71103r1_rule'
  tag stig_id: 'SRG-OS-000134-GPOS-00068'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-61737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
