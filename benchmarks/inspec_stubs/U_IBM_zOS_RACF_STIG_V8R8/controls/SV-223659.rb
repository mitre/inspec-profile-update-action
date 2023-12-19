control 'SV-223659' do
  title 'The IBM RACF MCS consoles resource class must be active.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

From the ISPF Command Shell enter:
SETRopts List

If the CONSOLE resource class is active, this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

The CONSOLE Class is activated with the command SETR CLASSACT(CONSOLE).

Generic profiles and commands should also be enabled with the command SETR GENERIC(CONSOLE) GENCMD(CONSOLE).

IBM recommends RACLISTing the CONSOLE Class which is accomplished with the command SETR RACL(CONSOLE).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25332r514666_chk'
  tag severity: 'medium'
  tag gid: 'V-223659'
  tag rid: 'SV-223659r604139_rule'
  tag stig_id: 'RACF-ES-000110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25320r514667_fix'
  tag 'documentable'
  tag legacy: ['V-98023', 'SV-107127']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
