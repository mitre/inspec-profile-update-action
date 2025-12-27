control 'SV-13886' do
  title 'A zone or name server does not have a backup administrator.'
  desc 'If there is no backup DNS administrator, then there is nobody to assist during a security emergency when the primary administrator is unavailable.  In some cases, a backup administrator can also detect problems introduced by the first administrator before these problems are allowed to propagate.  Personnel redundancy is as important as technology redundancy for the DNS availability.'
  desc 'check', 'If the site POC cannot produce a list of backup personnel authorized to administer each zone and name server, then this is a finding. If any zone or name server has only one DNS database administrator or only one DNS software administrator, then this is a finding. If there is not a backup administrator for both roles, then this is a finding.'
  desc 'fix', 'Working with appropriate resource managers, the IAO should identify a backup DNS administrator for each zone and name server under the IAOs scope of responsibility.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-9850r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13314'
  tag rid: 'SV-13886r1_rule'
  tag stig_id: 'DNS0125'
  tag gtitle: 'Zone/name server does not have backup admin.'
  tag fix_id: 'F-12566r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
