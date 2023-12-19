control 'SV-223514' do
  title 'ACF2 security data sets and/or databases must be properly protected.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.

Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

'
  desc 'check', 'Determine all associated ESM security data sets and/or databases.

If the ESM data set rules for ESM security data sets and/or databases restrict READ access to auditors and DASD batch, this is not a finding.

If the ESM data set rules for ESM security data sets and/or databases restrict READ and/or greater access to z/OS systems programming personnel, security personnel, and/or batch jobs that perform ACP maintenance, this is not a finding.

If all (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, ALTER, and CONTROL) for ACP security data sets and/or databases are logged, this is not a finding.'
  desc 'fix', 'Configure ESM READ and/or greater access rules for ESM files and/or databases as limited to system programmers and/or security personnel, and/or batch jobs that perform ACP maintenance. 

READ access can be given to auditors and DASD batch. All accesses to ACP files and/or databases are logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25187r504612_chk'
  tag severity: 'high'
  tag gid: 'V-223514'
  tag rid: 'SV-223514r533198_rule'
  tag stig_id: 'ACF2-ES-000970'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-25175r504613_fix'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-106837', 'V-97733']
  tag cci: ['CCI-000213', 'CCI-001084', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'SC-3', 'CM-5 (6)', 'AC-6 (10)']
end
