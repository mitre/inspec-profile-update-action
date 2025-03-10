control 'SV-223908' do
  title 'CA-TSS must limit Write or greater access to SYS1.UADS to system programmers only, and Read and Update access must be limited to system programmer personnel and/or security personnel.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'The ESM data set rules for SYS1.UADS restricts WRITE or Greater access to only z/OS systems programming personnel.

The ESM data set rules for SYS1.UADS restricts READ and/or UPDATE access to z/OS systems programming personnel and/or security personnel.

The ESM data set rules for SYS1.UADS specifies that all (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, ALTER, and CONTROL) will be logged.

The ESM data set rules for SYS1.UADS restricts READ access to auditors as documented in Security Plan.

If all of the above are untrue, this is not a finding.

If any of the above is true, this is a finding.'
  desc 'fix', 'Evaluate the impact of correcting any deficiency. Develop a plan of action and implement the changes as required to protect SYS1.UADS.
SYS1.UADS WRITE or Greater authority is limited to the systems programming staff. 

Read and update access should be limited to the security staff. 

READ access is limited to Auditors when included in the site security plan

Configure allocate access to SYS1.UADS to be limited to system programmers only, read and update access to SYS1.UADS to be limited to system programmer personnel and/or security personnel and all data set access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25581r516123_chk'
  tag severity: 'high'
  tag gid: 'V-223908'
  tag rid: 'SV-223908r856080_rule'
  tag stig_id: 'TSS0-ES-000350'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25569r516124_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98523', 'SV-107627']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
