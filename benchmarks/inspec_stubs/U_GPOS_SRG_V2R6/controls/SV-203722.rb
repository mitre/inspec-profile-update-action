control 'SV-203722' do
  title 'The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of white-listed software occurs prior to execution or at system startup.

This requirement applies to operating system programs, functions, and services designed to manage system processes and configurations (e.g., group policies).'
  desc 'check', 'Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3847r375173_chk'
  tag severity: 'medium'
  tag gid: 'V-203722'
  tag rid: 'SV-203722r851793_rule'
  tag stig_id: 'SRG-OS-000370-GPOS-00155'
  tag gtitle: 'SRG-OS-000370'
  tag fix_id: 'F-3847r375174_fix'
  tag 'documentable'
  tag legacy: ['SV-71101', 'V-56841']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
