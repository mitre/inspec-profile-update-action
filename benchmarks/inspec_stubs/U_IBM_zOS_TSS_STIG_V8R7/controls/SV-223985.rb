control 'SV-223985' do
  title 'IBM z/OS JES2.** resource must be properly protected in the CA-TSS database.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From the ISPF Command Shell enter:
WHOOWNS OPERCMDS(JES2)
NOTE: JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem. 

If the JES2. resource is not owned, or is owned inappropriately, in the OPERCMDS class, this is a finding.'
  desc 'fix', 'The JES2. resource must be owned in the OPERCMDS class. 

NOTE: JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem. 

Extended MCS support allows the installation to control the use of JES2 system commands through the ACP. These commands are subject to various types of potential abuse. For this reason, it is necessary to place restrictions on the JES2 system commands that can be entered by particular operators. To control access to JES2 system commands, the following recommendations will be applied when implementing security:

For Example:
The following command may be used to establish default protection for JES2 system commands defined to the OPERCMDS resource class:

TSS ADDTO(deptacid) OPERCMDS(JES2.)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25658r516354_chk'
  tag severity: 'medium'
  tag gid: 'V-223985'
  tag rid: 'SV-223985r561402_rule'
  tag stig_id: 'TSS0-JS-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25646r516355_fix'
  tag 'documentable'
  tag legacy: ['V-98677', 'SV-107781']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
