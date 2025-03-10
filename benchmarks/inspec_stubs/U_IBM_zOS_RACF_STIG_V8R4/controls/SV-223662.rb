control 'SV-223662' do
  title 'IBM RACF USERIDs possessing the Tape Bypass Label Processing (BLP) privilege must be justified.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From the ISPF Command Shell enter:
RLIST FACILITY ICHBLP AUTHUSER

If access authorization to the ICHBLP resource is restricted at the userid level to data center personnel (e.g., tape librarian, operations staff, etc.), this is not a finding.

If no tape management system (e.g., CA-1) is installed the following:
From the ISPF Command Shell enter:
SETROPTS LIST

If the TAPEVOL class is active, this is not a finding.'
  desc 'fix', 'Review all USERIDs with the BLP attribute. Ensure documentation providing justification for access is maintained and filed with the ISSO, and that unjustified access is removed.

BLP is controlled thru the FACILITY class profile ICHBLP. Access is removed with the following command:
PE ICHBLP CL(FACILITY) id(<userid>) DELETE
a subsequent REFRESH of the FACILITY class may be required via the command: SETR RACL(FACILITY) REFRESH'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25335r514675_chk'
  tag severity: 'medium'
  tag gid: 'V-223662'
  tag rid: 'SV-223662r604139_rule'
  tag stig_id: 'RACF-ES-000140'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25323r514676_fix'
  tag 'documentable'
  tag legacy: ['V-98029', 'SV-107133']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
