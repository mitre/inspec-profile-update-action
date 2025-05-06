control 'SV-251593' do
  title 'All installation-delivered IDMS DC-Administrator-level programs must be properly secured.'
  desc 'DC Administrator-level programs that are not secured may allow unauthorized users to use them to access and manipulate various resources within the DBMS.

'
  desc 'check', 'The following are DC-administrator level batch programs and are executed using JCL rather than the CV. As batch programs, they need to be secured in the external security manager (ESM) rather than through the SRTT.

Validate the following suggested DBA-level programs are secured by the ESM:
IDMSDIRL
RHDCSGEN
RHDCTTBL

If the suggested DC-Administrator-level programs are not secured in the SRTT and have not been authorized for DCADMINs in the ESM, this is a finding. (Note that USER, DEVELOPER, DBADMIN and DCADMIN are suggested categories only).

Contact the security office if the programs in this list are not secured, for this is a finding.'
  desc 'fix', 'Contact the security office to confirm that the programs in this list are secured via the ESM and assigned to the appropriate users. Each program in the list must be secured.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55028r807644_chk'
  tag severity: 'medium'
  tag gid: 'V-251593'
  tag rid: 'SV-251593r807646_rule'
  tag stig_id: 'IDMS-DB-000130'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54982r807645_fix'
  tag satisfies: ['SRG-APP-000033-DB-000084', 'SRG-APP-000211-DB-000122']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001082']
  tag nist: ['AC-3', 'SC-2']
end
