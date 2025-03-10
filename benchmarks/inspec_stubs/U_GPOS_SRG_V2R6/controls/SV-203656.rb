control 'SV-203656' do
  title 'The operating system must isolate security functions from nonsecurity functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify the operating system isolates security functions from nonsecurity functions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to isolate security functions from nonsecurity functions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3781r557213_chk'
  tag severity: 'medium'
  tag gid: 'V-203656'
  tag rid: 'SV-203656r557215_rule'
  tag stig_id: 'SRG-OS-000134-GPOS-00068'
  tag gtitle: 'SRG-OS-000134'
  tag fix_id: 'F-3781r557214_fix'
  tag 'documentable'
  tag legacy: ['V-56843', 'SV-71103']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
