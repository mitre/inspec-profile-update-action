control 'SV-223660' do
  title 'IBM RACF CLASSACT SETROPTS must be specified for the TEMPDSN class.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

From the ISPF Command Shell enter:
SETRopts List

If the TEMPDSN resource class is ACTIVE, this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

The TEMPDSN Class is activated with the command SETR CLASSACT(TEMPDSN).

Generic profiles and commands should also be enabled with the command SETR GENERIC(TEMPDSN) GENCMD(TEMPDSN).

IBM recommends RACLISTing the TEMPDSN Class which is accomplished with the command SETR RACL(TEMPDSN).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25333r514669_chk'
  tag severity: 'medium'
  tag gid: 'V-223660'
  tag rid: 'SV-223660r604139_rule'
  tag stig_id: 'RACF-ES-000120'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25321r514670_fix'
  tag 'documentable'
  tag legacy: ['V-98025', 'SV-107129']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
