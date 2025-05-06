control 'SV-252920' do
  title 'TOSS must use a Linux Security Module configured to enforce limits on system services.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from non-security functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Verify that TOSS verifies the correct operation of all security functions.

Check if "SELinux" is active and in "Enforcing" mode with the following command:

$ sudo getenforce
Enforcing

If "SELinux" is not active or not in "Enforcing" mode, this is a finding.'
  desc 'fix', 'Configure the operating system to verify correct operation of all security functions.

Set the "SELinux" status and the "Enforcing" mode by modifying the "/etc/selinux/config" file to have the following line:

SELINUX=enforcing

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56373r824082_chk'
  tag severity: 'medium'
  tag gid: 'V-252920'
  tag rid: 'SV-252920r824084_rule'
  tag stig_id: 'TOSS-04-010090'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-56323r824083_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
