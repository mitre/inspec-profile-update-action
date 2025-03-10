control 'SV-251592' do
  title 'All installation-delivered IDMS Database-Administrator-level programs must be properly secured.'
  desc 'DBA-level programs that are not secured may allow unauthorized users to use them to access and manipulate various resources within the DBMS.

'
  desc 'check', 'The following are DBA-level batch programs and are executed using JCL rather than the CV. As batch programs, they need to be secured for DBAs in the external security manager (ESM) (included in DCADMIN, DBADMIN level security) rather than through the SRTT.

Validate the following suggested DBA-level programs are secured by the ESM.
ADSOBSYS
ADSOBTAT
IDMSCHEM
IDMSDBN1
IDMSDBN2
IDMSDDDL
IDMSPASS
IDMSRSTC
IDMSUBSC
RHDCOMVS

Contact the security office to confirm that the programs in this list are secured. If not, this is a finding.'
  desc 'fix', 'Contact the security office to confirm that the programs in this list are secured via the ESM and assigned to the appropriate users. Each program in the list must be secured.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55027r807641_chk'
  tag severity: 'medium'
  tag gid: 'V-251592'
  tag rid: 'SV-251592r807643_rule'
  tag stig_id: 'IDMS-DB-000120'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54981r807642_fix'
  tag satisfies: ['SRG-APP-000033-DB-000084', 'SRG-APP-000211-DB-000122']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001082']
  tag nist: ['AC-3', 'SC-2']
end
