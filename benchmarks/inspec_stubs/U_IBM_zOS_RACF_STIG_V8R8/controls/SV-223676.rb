control 'SV-223676' do
  title 'IBM RACF must limit Write or greater access to SYS1.LPALIB to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute a dataset list of access for SYS1.LPALIB.

If any of the following is true, this is a finding.

-The ESM data set rules for SYS1.LPALIB do not restrict WRITE or greater access to only z/OS systems programming personnel.
-The ESM data set rules for SYS1.LPALIB do not specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect SYS1.LPALIB. 

Configure WRITE or greater access to SYS1.LPALIB to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25349r514717_chk'
  tag severity: 'high'
  tag gid: 'V-223676'
  tag rid: 'SV-223676r853581_rule'
  tag stig_id: 'RACF-ES-000280'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25337r514718_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98057', 'SV-107161']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
