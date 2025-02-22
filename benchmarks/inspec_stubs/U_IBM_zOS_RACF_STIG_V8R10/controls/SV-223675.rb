control 'SV-223675' do
  title 'IBM RACF must limit Write or greater access to SYS1.SVCLIB to appropriate authorized users.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute a dataset list of access for SYS1.SVCLIB.

If all of the following are true, this is not a finding.

If any of the following are untrue, this is a finding.

-ESM data set rules for SYS1.SVCLIB restrict WRITE or greater access to only z/OS systems programming personnel.
-ESM data set rules for SYS1.SVCLIB specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Configure Write or greater access to SYS1.SVCLIB to be limited to system programmers only and all WRITE or greater access is logged and reviewed. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes for SYS1.SVCLIB. SYS1.SVCLIB contains SVCs and I/O appendages as such: they are very powerful and will be strictly controlled to avoid compromising system integrity.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25348r514714_chk'
  tag severity: 'high'
  tag gid: 'V-223675'
  tag rid: 'SV-223675r853580_rule'
  tag stig_id: 'RACF-ES-000270'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25336r514715_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107159', 'V-98055']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
