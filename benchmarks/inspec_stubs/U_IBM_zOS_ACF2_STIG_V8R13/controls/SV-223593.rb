control 'SV-223593' do
  title 'IBM z/OS DFSMS resource class(es) must be defined to the GSO CLASMAP record in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

The system-wide options control the default settings for determining how the ACP will function when handling requests for access to the operating system environment, ACP, and customer data. The ACP provides the ability to set a number of these fields at the subsystem level. If no setting is found, the system-wide defaults will be used. The improper setting of any one of these fields, individually or in combination with another, can compromise the security of the processing environment. In addition, failure to establish standardized settings for the ACP control options introduces the possibility of exposure during a migration process or contingency plan activation.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET CONTROL(GSO)
SHOW CLASMAP

If both MGMTCLAS and STORCLAS resource classes are uniquely defined (i.e., not type SAF), this is not a finding.'
  desc 'fix', 'Define the GSO CLASMAP record with the following definitions:

MGMTCLAS
STORCLAS

Ensure both resource classes above are defined uniquely.

Example:
SHOW SAFDEF

SET CONTROL(GSO)
INSERT CLASMAP.MGMTCLAS RESOURCE(MGMTCLAS) RSRCTYPE(MGM) ENTITYTLN(8)
INSERT CLASMAP.STORCLAS RESOURCE(STORCLAS) RSRCTYPE(STR) ENTITYTLN(8
F ACF2,REFRESH(ALL)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25266r836678_chk'
  tag severity: 'medium'
  tag gid: 'V-223593'
  tag rid: 'SV-223593r836696_rule'
  tag stig_id: 'ACF2-SM-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25254r836679_fix'
  tag 'documentable'
  tag legacy: ['V-97891', 'SV-106995']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
