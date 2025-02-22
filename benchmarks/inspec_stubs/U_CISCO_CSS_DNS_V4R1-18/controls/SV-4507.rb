control 'SV-4507' do
  title 'The Cisco CSS DNS is utilized to host the organizations authoritative records and DISA Computing Services does not support that host in its csd.disa.mil domain and associated high-availability server infrastructure.'
  desc 'The primary security concern with regard to the type of delegation discussed is that to implement this approach, an organization would have to migrate its authoritative records from a well-known DNS implementation with proven, tested security controls to a relatively new DNS implementation without similar controls.  Therefore, this migration should only occur when the performance and availability advantages of CSS significantly outweigh the increased residual security risk of using a less mature technology.'
  desc 'check', 'Determine whether the CSS DNS device is used as an authoritative name server.  If the CSS DNS does maintain authoritative records, then this is a finding.  The exception to this is if this CSS DNS device supports authoritative records for a host(s) within the csd.disa.mil domain, which is not a finding.

Instruction:  In the presence of the reviewer, the CSS DNS administrator should enter the following command while in global configuration mode:

show dns-record statistics

If any of the hosts have domain names outside of the csd.disa.mil domain, then this is a finding.'
  desc 'fix', 'The CSS DSN administrator should use the following command while in global command mode; no dns-record, to remove domain records that do not support hosts in the csd.disa.mil domain.'
  impact 0.5
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-3408r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4507'
  tag rid: 'SV-4507r1_rule'
  tag stig_id: 'DNS0905'
  tag gtitle: 'The Cisco CSS DNS hosts authoritative records.'
  tag fix_id: 'F-4392r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
