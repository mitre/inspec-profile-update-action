control 'SV-223658' do
  title 'The IBM RACF OPERCMDS resource class must be active.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

From the ISPF Command Shell enter:
SETRopts List

If the OPERCMDS resource class is active, this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

The OPERCMDS Class is activated with the command SETR CLASSACT(OPERCMDS).

Generic profiles and commands should also be enabled with the command SETR GENERIC(OPERCMDS) GENCMD(OPERCMDS).

IBM recommends RACLISTing the OPERCMDSClass which is accomplished with the command SETR RACL(OPERCMDS).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25331r514663_chk'
  tag severity: 'medium'
  tag gid: 'V-223658'
  tag rid: 'SV-223658r604139_rule'
  tag stig_id: 'RACF-ES-000100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25319r514664_fix'
  tag 'documentable'
  tag legacy: ['V-98021', 'SV-107125']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
