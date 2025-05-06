control 'SV-207402' do
  title 'The VMM must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the VMM responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. VMMs implement code separation (i.e., separation of security functions from non-security functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code. 

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of guest VMs, memory space, and libraries. VMMs restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify the VMM isolates security functions from non-security functions. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to isolate security functions from non-security functions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7659r365616_chk'
  tag severity: 'medium'
  tag gid: 'V-207402'
  tag rid: 'SV-207402r378973_rule'
  tag stig_id: 'SRG-OS-000134-VMM-000660'
  tag gtitle: 'SRG-OS-000134'
  tag fix_id: 'F-7659r365617_fix'
  tag 'documentable'
  tag legacy: ['SV-71265', 'V-57005']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
