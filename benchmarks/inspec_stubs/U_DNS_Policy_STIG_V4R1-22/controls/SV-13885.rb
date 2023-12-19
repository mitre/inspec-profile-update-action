control 'SV-13885' do
  title 'The underlying operating system of the DNS server is not in compliance with the appropriate OS STIG.'
  desc 'A vulnerability in the underlying operating system of a DNS server could potentially impact not only the DNS server but the entire network infrastructure to include the Global Information Grid (GIG).'
  desc 'check', 'Review the Operating System against the appropriate OS STIG. For a Windows system this would mean an evaluation with the Gold Disk; for a UNIX/LINUX system this would mean an evaluation using the SRR scripts. STIG compliance means that all findings are either closed, or there is a POA&M to address any outstanding vulnerabilities.'
  desc 'fix', 'The underlying Operating System of the DNS server must be in compliance with the appropriate OS STIG.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-9849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13313'
  tag rid: 'SV-13885r1_rule'
  tag stig_id: 'DNS0170'
  tag gtitle: 'OS on DNS server not STIG compliant.'
  tag fix_id: 'F-11160r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
