control 'SV-223667' do
  title 'IBM RACF must limit Write or greater access to SYS1.UADS to system programmers only, and WRITE or greater access must be limited to system programmer personnel and/or security personnel.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'The ESM data set rules for SYS1.UADS restrict WRITE or Greater access to only z/OS systems programming personnel.

The ESM data set rules for SYS1.UADS restrict READ and/or UPDATE access to z/OS systems programming personnel and/or security personnel.

The ESM data set rules for SYS1.UADS restrict READ access to auditors as documented in Security Plan.

The ESM data set rules for SYS1.UADS specify that all (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, ALTER, and CONTROL) will be logged.

If all of the above are untrue, this is not a finding.

If any of the above is true, this is a finding.'
  desc 'fix', 'Evaluate the impact of correcting any deficiency. Develop a plan of action and implement the changes as required to protect SYS1.UADS.
SYS1.UADS WRITE or Greater authority is limited to the systems programming staff. 
READ and/or UPDATE access should be limited to the security staff.
READ access is limited to Auditors when included in the site security plan.
Configure allocate access to SYS1.UADS to be limited to system programmers only, Read and Update access to SYS1.UADS to be limited to system programmer personnel and/or security personnel, and all dataset access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25340r514690_chk'
  tag severity: 'high'
  tag gid: 'V-223667'
  tag rid: 'SV-223667r853573_rule'
  tag stig_id: 'RACF-ES-000190'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25328r514691_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98039', 'SV-107143']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
