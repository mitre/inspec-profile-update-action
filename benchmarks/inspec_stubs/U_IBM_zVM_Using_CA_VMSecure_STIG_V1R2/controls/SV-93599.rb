control 'SV-93599' do
  title 'CA VM:Secure must have a security group for Security Administrators only.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from non-security functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Ask the Security Administrator for the defined groups that have authorization to perform security tasks, i.e., create and change rules for any userID in the Rules Facility.

Examine the members (users) in each of these groups.

If any user does not have the role of Security Administrator, this is a finding.'
  desc 'fix', 'Define a security group in the Rules Facility for Security Administrators only.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78479r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78893'
  tag rid: 'SV-93599r1_rule'
  tag stig_id: 'IBMZ-VM-000700'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-85643r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
