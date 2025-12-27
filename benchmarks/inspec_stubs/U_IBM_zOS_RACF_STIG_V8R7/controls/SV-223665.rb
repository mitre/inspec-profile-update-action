control 'SV-223665' do
  title 'IBM RACF Global Access Checking must be restricted to appropriate classes and resources.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From a command input screen enter:
RL Global *

If Global * is specified in SETROPTS, this is a finding.

The following entries may be allowed with the approval of the ISSM:
Dataset Class - ALTER access level to &RACUID.** (Allows users all access to their own datasets)
OPERCMDS Class – READ access to MVS.MCSOPER.&RACUID (Allows users access to console for their jobs) 
JESJOBS Class – ALTER access to CANCEL.*.*.&RACUID (Allows users to cancel their own jobs)
JESJOBS Class – ALTER access to SUBMIT.*.*.&RACUID (Allows users to submit their own jobs)

The ISSM may allow other classes to be included after evaluation with the system programmer.

If any other members are included for Global Access Checking, this is a finding.

If written approval by the ISSM is not provided, this is a finding.'
  desc 'fix', 'Configure Global Access Checking to be appropriately administered.

Evaluate the impact associated with implementation of the control option. Develop approval; documentation and a plan of action to implement the control option as specified in the example below: 
RALT GLOBAL class-name
ADDMEM (resourcename)/accesslevel)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25338r514684_chk'
  tag severity: 'medium'
  tag gid: 'V-223665'
  tag rid: 'SV-223665r604139_rule'
  tag stig_id: 'RACF-ES-000170'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25326r514685_fix'
  tag 'documentable'
  tag legacy: ['SV-107139', 'V-98035']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
