control 'SV-251591' do
  title 'All installation-delivered IDMS Developer-level Programs must be properly secured.'
  desc 'Developer-level programs that are not secured may allow unauthorized users to access and manipulate various resources within the DBMS.

'
  desc 'check', 'The following are developer-level batch programs and are executed using JCL rather than the CV. As batch programs, they need to be secured in the external security manager (ESM) rather than through the SRTT.

Validate the following suggested developer-level programs are secured by the ESM.
ADSOBCOM
ADSORPTS
IDMSDMLA
IDMSDMLC
IDMSDMLP
IDMSLOOK
IDMSRPTS
RHDCMAP1
RHDCMPUT   
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
Contact the security office to confirm that the programs in this list are secured. If they are not, this is a finding.'
  desc 'fix', 'Contact the security office to confirm that the programs in this list are secured via the ESM and assigned to the appropriate users. Each program in the list must be secured.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55026r807638_chk'
  tag severity: 'medium'
  tag gid: 'V-251591'
  tag rid: 'SV-251591r807640_rule'
  tag stig_id: 'IDMS-DB-000110'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54980r807639_fix'
  tag satisfies: ['SRG-APP-000033-DB-000084', 'SRG-APP-000211-DB-000122']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001082']
  tag nist: ['AC-3', 'SC-2']
end
