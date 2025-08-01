control 'SV-4508' do
  title 'Zones are delegated with the CSS DNS.'
  desc 'Although it is technically possible to delegate zones within CSS DNS, there is almost never a rationale to do so because such delegation could be achieved as easily with BIND, which offers security features not present in CSS DNS.  Moreover, the performance enhancing features of CSS typically would not apply to name server records because these records are obtained easily and quickly across the wide area without significant impact on a users experience'
  desc 'check', 'In the presence of the reviewer, the CSS DNS administrator should enter the following command while in global configuration mode:

show dns-record statistics

There should be no DNS record types of NS.  If there are NS records, then this is a finding.'
  desc 'fix', 'The CSS DNS administrator should remove any NS records with the following command while in global configuration mode; no dns-record ns domain_name.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3416r1_chk'
  tag severity: 'low'
  tag gid: 'V-4508'
  tag rid: 'SV-4508r1_rule'
  tag stig_id: 'DNS0910'
  tag gtitle: 'Zones are delegated with the CSS DNS.'
  tag fix_id: 'F-4393r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
