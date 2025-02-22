control 'SV-223465' do
  title 'CA-ACF2 must limit update and allocate access to the JES2 System data sets (e.g., Spool, Checkpoint, and Initialization parameters) to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'The ESM data set rules for the JES2 System data sets (e.g., Spool, Checkpoint, and Initialization parameters) do not restrict UPDATE and/or ALTER access to only z/OS systems programming personnel.

The ESM data set rules for the JES2 System data sets (e.g., Spool, Checkpoint, and Initialization parameters) allow inappropriate access not documented and approved by ISSO.

If both of the above are untrue, this is not a finding.

If either of the above are true, this is a finding.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect System-level product installation libraries.

Configure allocate access to all system-level product execution libraries to be limited to system programmers only.

Access other than this should be documented and approved by the ISSO.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25138r504513_chk'
  tag severity: 'medium'
  tag gid: 'V-223465'
  tag rid: 'SV-223465r533198_rule'
  tag stig_id: 'ACF2-ES-000470'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25126r504514_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-97629', 'SV-106733']
  tag cci: ['CCI-001499', 'CCI-000213', 'CCI-002235']
  tag nist: ['CM-5 (6)', 'AC-3', 'AC-6 (10)']
end
