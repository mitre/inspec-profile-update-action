control 'SV-251642' do
  title 'CA IDMS must protect the system code and storage from corruption by user programs.'
  desc 'Database management systems can maintain separate execution domains for each executing process by assigning each process a separate address space. Each process has a distinct address space so that communication between processes is controlled through the security functions, and one process cannot modify the executing code of another process. Maintaining separate execution domains for executing processes can be achieved, for example, by implementing separate address spaces.'
  desc 'check', 'Log on to IDMS DC system and issue DCPROFIL. 

If HPSPO ENABLED: display is "NO", this is a finding.'
  desc 'fix', 'Use the following system generation parameters to enable the use of high performance storage protection:
 
Set STORAGE KEY parameter of the SYSTEM statement to "9".

Set PROTECT/NOPROTECT parameter of the SYSTEM statement to "PROTECT".

Set PROTECT/NOPROTECT parameter of the PROGRAM statement to "PROTECT" for PROGRAMS required to run with the alternate protect key (i.e., 9).

DCMT DISPLAY ALL STORAGE POOLS can be used to take note of what pools support any type of user storage, that is, user, user-kept, shared, shared-kept, or ALL, in preparation for the next step.

If necessary, redefine storage pools in such a manner that all forms of user-oriented storage (user, user-kept, shared, and shared-kept) are segregated from the system storage (database, terminal). For example: 
ADD STORAGE POOL 1
 CONTAINS TYPES ( SHARED SHARED-KEPT USER USER-KEPT )
 ADD XA STORAGE POOL 128
 CONTAINS TYPES ( USER USER-KEPT )
 ADD XA STORAGE POOL 129
CONTAINS TYPES ( SHARED SHARED-KEPT )
 ADD XA STORAGE POOL 130
 CONTAINS TYPES ( TERMINAL DATABASE )

Generate and start the system. The storage pool definitions have been set up correctly if the message DC004001 HPSPO HAS BEEN DISABLED DUE TO INCORRECT STORAGE POOL DEFINITIONS is not issued at startup.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55077r807791_chk'
  tag severity: 'medium'
  tag gid: 'V-251642'
  tag rid: 'SV-251642r807793_rule'
  tag stig_id: 'IDMS-DB-000780'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-55031r807792_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
