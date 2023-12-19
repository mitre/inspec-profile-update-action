control 'SV-74287' do
  title 'Owners of privileged accounts must use non-privileged accounts for non-administrative activities.'
  desc 'Use of privileged accounts for non-administrative purposes puts data at risk of unintended or unauthorized loss, modification, or exposure. In particular, DBA accounts, if used for non-administration application development or application maintenance, can lead to excessive privileges where privileges are inherited by object owners. It may also lead to loss or compromise of application data where the elevated privileges bypass controls designed in and provided by applications.'
  desc 'check', 'Review procedures and practices.  If there is not a policy requiring owners of privileged accounts to use non-privileged accounts for non-administrative activities, this is a finding.  If there is evidence that owners of privileged accounts do not adhere to this policy, this is a finding.'
  desc 'fix', 'Require that DBAs and other privileged users use non-privileged accounts for non-administrative activities.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-60603r1_chk'
  tag severity: 'medium'
  tag gid: 'V-59857'
  tag rid: 'SV-74287r1_rule'
  tag stig_id: 'SQL2-00-009710'
  tag gtitle: 'SRG-APP-000063-DB-000018'
  tag fix_id: 'F-65267r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
