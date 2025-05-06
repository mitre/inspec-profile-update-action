control 'SV-223965' do
  title 'The IBM z/OS IEASYMUP resource must be protected in accordance with proper security requirements.'
  desc 'Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS IBMFAC(IEASYMUP)

If the TSS resources are owned or DEFPROT is specified for the resource class, this is not a finding.

Enter
TSS WHOHAS IBMFAC(IEASYMUP)

If TSS resource access authorizations restrict UPDATE and/or greater access to DASD administrators, Tape Library personnel, and system programming personnel, this is not a finding.'
  desc 'fix', 'Ensure that the System level symbolic resources are defined to the FACILITY resource class and protected. UPDATE access to the System level symbolic resources are limited to System Programmers, DASD Administrators, and/or Tape Library personnel. All access is logged. Ensure the guidelines for the resources and/or generic equivalent are followed.

Limit access to the IEASYMUP resources to above personnel with UPDATE and/or greater access.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(ADMIN) IBMFAC(IEASYMUP)

TSS PERMIT(<dasdsmpl>) IBMFAC(IEASYMUP) ACC(U) ACTION(AUDIT)
TSS PERMIT(<syspsmpl>) IBMFAC(IEASYMUP) ACC(U) ACTION(AUDIT)
TSS PERMIT(<tapesmpl>) IBMFAC(IEASYMUP) ACC(U) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25638r516294_chk'
  tag severity: 'medium'
  tag gid: 'V-223965'
  tag rid: 'SV-223965r856102_rule'
  tag stig_id: 'TSS0-ES-000920'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25626r516295_fix'
  tag 'documentable'
  tag legacy: ['V-98637', 'SV-107741']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
