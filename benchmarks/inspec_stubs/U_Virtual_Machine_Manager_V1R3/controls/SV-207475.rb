control 'SV-207475' do
  title 'The VMM must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and guest VMs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software and guest VMs. Using only authorized software decreases risk by limiting the number of potential vulnerabilities and by preventing the execution of malware.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs and guest VMs that are authorized to execute on organizational VMMs is commonly referred to as whitelisting.

Verification of white-listed software and guest VMs can occur either prior to execution or at system startup.'
  desc 'check', 'Verify the VMM employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs and guest VMs.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and guest VMs.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7732r365829_chk'
  tag severity: 'medium'
  tag gid: 'V-207475'
  tag rid: 'SV-207475r854649_rule'
  tag stig_id: 'SRG-OS-000370-VMM-001460'
  tag gtitle: 'SRG-OS-000370'
  tag fix_id: 'F-7732r365830_fix'
  tag 'documentable'
  tag legacy: ['SV-71411', 'V-57151']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
