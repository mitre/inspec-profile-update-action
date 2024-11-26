control 'SV-223988' do
  title 'IBM z/OS JES2 input sources must be properly controlled.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS JESINPUT(*)
For each resource owned 

If all of the TSS resources and/or generic equivalent identified above are defined with access restricted to the appropriate personnel, this is not a finding.

If any of the TSS resources and/or generic equivalent identified above are not defined with access restricted to the appropriate personnel, this is a finding.

From the ISPF Command Shell enter:
TSS LIST RDT(*)

If the JESINPT RESOURCE does not have DEFPROT as an attribute, this is a finding.'
  desc 'fix', 'Configure access authorization for resources defined to the JESINPUT resource class to be restricted to the appropriate personnel.

Grant read access to authorized users for each of the following input sources:

INTRDR
nodename
OFFn.*
OFFn.JR
OFFn.SR
Rnnnn.RDm
RDRnn
STCINRDR
TSUINRDR and/or TSOINRDR

The resource definition will be generic if all of the resources of the same type have identical access controls (e.g., if all off load receivers are equivalent). The default access will be NONE except for sources that are permitted to submit jobs for all users. Those resources may be defined as either NONE or READ.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25661r516363_chk'
  tag severity: 'medium'
  tag gid: 'V-223988'
  tag rid: 'SV-223988r877829_rule'
  tag stig_id: 'TSS0-JS-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25649r516364_fix'
  tag 'documentable'
  tag legacy: ['SV-107787', 'V-98683']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
