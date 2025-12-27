control 'SV-251621' do
  title 'CA IDMS must limit the use of dynamic statements in applications, procedures, and exits to circumstances determined by the organization.'
  desc 'Dynamic SQL statements are compiled at runtime and, if manipulated by an unauthorized user, can produce an innumerable array of undesired results. These statements should not be used casually.'
  desc 'check', 'If EXECUTE IMMEDIATE, PREPARE, and EXECUTE statements are found while reviewing source code in applications, procedures, and exits in code that does not require it, this is a finding.'
  desc 'fix', 'Modify the code to remove the dynamic statements EXECUTE IMMEDIATE, PREPARE, and EXECUTE. If these statements must be used, use other measures to eliminate possible code injection success by securing resources (databases, access modules, tasks, programs, etc.). Since security checks are issued by CA IDMS as it executes the commands and the authorization permissions are cached for the life of the transaction or task, whichever ends first. The use of strongly typing parameters and validating inputs are other ways to guard against code injection when dynamic statement execution must be used.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55056r807728_chk'
  tag severity: 'medium'
  tag gid: 'V-251621'
  tag rid: 'SV-251621r808358_rule'
  tag stig_id: 'IDMS-DB-000500'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-55010r807729_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
