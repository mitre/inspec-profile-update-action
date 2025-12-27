control 'SV-13619' do
  title 'The DNS server software is either installed on or enabled on an operating system that is no longer supported by the vendor.'
  desc 'check', 'Review the Operating System to determine if it is supported by the vendor, e.g. Windows NT is no longer supported.'
  desc 'fix', 'The IAO should develop a migration plan to upgrade or replace any out of date software or any software that is no longer vendor supported.'
  impact 0.7
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-7863r1_chk'
  tag severity: 'high'
  tag gid: 'V-13051'
  tag rid: 'SV-13619r1_rule'
  tag stig_id: 'DNS0175'
  tag gtitle: 'OS on DNS no longer vendor supported.'
  tag fix_id: 'F-11161r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'VIVM-1'
end
