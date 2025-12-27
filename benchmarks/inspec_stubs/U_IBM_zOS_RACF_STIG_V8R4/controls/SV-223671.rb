control 'SV-223671' do
  title 'IBM RACF must limit access to SYS(x).TRACE to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute a dataset list of access for SYS(x).TRACE files.

If the ESM data set rule for SYS1.TRACE restricts access to systems programming personnel and started tasks that perform GTF processing, this is not a finding.

If the ESM data set rule for SYS1.TRACE restricts access to others as documented and approved by ISSM, this is not a finding.'
  desc 'fix', 'Configure the ESM access to SYS1.TRACE to be limited to system programmers or started tasks that perform GTF processing.
Other user access can be granted as documented and approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25344r514702_chk'
  tag severity: 'medium'
  tag gid: 'V-223671'
  tag rid: 'SV-223671r604139_rule'
  tag stig_id: 'RACF-ES-000230'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25332r514703_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98047', 'SV-107151']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
