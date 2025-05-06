control 'SV-223678' do
  title 'IBM RACF must limit write or greater access to all LPA libraries to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'From Any ISPF input line, enter:
TSO ISRDDN LPA. 

If any of the following is true, this is a finding.

-The ACP data set rules for LPA libraries do not restrict WRITE or greater access to only z/OS systems programming personnel.
-The ACP data set rules for LPA libraries do not specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect LPA Libraries.

Configure the WRITE or greater access to all LPA libraries to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25351r514723_chk'
  tag severity: 'high'
  tag gid: 'V-223678'
  tag rid: 'SV-223678r604139_rule'
  tag stig_id: 'RACF-ES-000300'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25339r514724_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98061', 'SV-107165']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
