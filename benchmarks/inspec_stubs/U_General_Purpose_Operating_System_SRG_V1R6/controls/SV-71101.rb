control 'SV-71101' do
  title 'The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of white-listed software occurs prior to execution or at system startup.

This requirement applies to operating system programs, functions, and services designed to manage system processes and configurations (e.g., group policies).'
  desc 'check', 'Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57413r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56841'
  tag rid: 'SV-71101r2_rule'
  tag stig_id: 'SRG-OS-000370-GPOS-00155'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-61739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
