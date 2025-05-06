control 'SV-251590' do
  title 'All installation-delivered IDMS User-level programs must be properly secured.'
  desc 'If user-level programs are not secured, then unauthorized users may use them to access and manipulate various resources within the DBMS.

'
  desc 'check', 'The following are user-level batch programs that are executed using JCL rather than by the CV. As batch programs, they need to be secured by the external security manager (ESM) rather than through the SRTT.

Validate the following suggested user-level programs are secured by the ESM:
ADSBATCH
ADSOBPLG
CULPRIT
IDMSBCF
OLQBATCH
OLQBNOTE

Contact the security office to confirm that the programs in this list are secured. If the programs listed are not secured, this is a finding.'
  desc 'fix', 'Contact the security office to confirm that the programs in this list are secured via the ESM and assigned to the appropriate users. Each program listed must be secured.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55025r807635_chk'
  tag severity: 'medium'
  tag gid: 'V-251590'
  tag rid: 'SV-251590r807637_rule'
  tag stig_id: 'IDMS-DB-000100'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54979r807636_fix'
  tag satisfies: ['SRG-APP-000033-DB-000084', 'SRG-APP-000211-DB-000122']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-001082']
  tag nist: ['AC-3', 'SC-2']
end
