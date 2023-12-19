control 'SV-223663' do
  title 'IBM RACF DASD volume-level protection must be properly defined.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From the ISPF Command Shell enter:
RLIST DASDVOL AUTHUSER

If a profile of "**" is defined for the "DASDVOL" resource class, this is not finding.

If access authorization to "DASDVOL" profiles is restricted to Storage Management Personnel, Storage Management Batch Userids, and Systems Programmers, this is not a finding.

If all (i.e., failures and successes) access is logged, this is not a finding.'
  desc 'fix', 'Develop a plan of action to implement the required changed.

Define profiles in the "DASDVOL" class. A sample command is provided here: 
RDEF DASDVOL ** UACC(NONE) OWNER(<StgMgmtGrp>) AUDIT(ALL(READ)).

More specific "DASDVOL" profiles should be defined to protect groups of "DASDVOLs". A sample command to create a profile protecting all DASDVOLs beginning with "SYS" is provided here: 
RDEF DASDVOL SYS* UACC(NONE) OWNER(<StgMgmtGrp>) AUDIT(ALL(READ)).

Permission can be granted to "DASDVOL" profiles. A sample command is provided here: 
PE SYS* CLASS(DASDVOL) ID(<syspsmpl>) ACCESS(ALTER)

If any profiles are in "WARN" mode, they should be reset. A sample command is provided here: 
RALT DASDVOL <profilename> NOWARN.

Note that the "GDASDVOL" class can also be used. See the RACF Security Admin Guide for more information.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25336r514678_chk'
  tag severity: 'medium'
  tag gid: 'V-223663'
  tag rid: 'SV-223663r604139_rule'
  tag stig_id: 'RACF-ES-000150'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25324r514679_fix'
  tag 'documentable'
  tag legacy: ['SV-107135', 'V-98031']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
