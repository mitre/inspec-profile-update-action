control 'SV-223957' do
  title 'The CA-TSS Facility Control Option must specify the sub option of MODE=FAIL.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of white-listed software occurs prior to execution or at system startup.

This requirement applies to operating system programs, functions, and services designed to manage system processes and configurations (e.g., group policies).'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY(FACILITY(ALL))

If the Facility Control Option does not specifies the sub option of "MODE=FAIL" for all facilities, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the Facility Control Option MODE sub-option. Develop a plan of action to implement the Facility Control Option MODE sub-option setting to "MODE=FAIL" and proceed with the change.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25630r516270_chk'
  tag severity: 'high'
  tag gid: 'V-223957'
  tag rid: 'SV-223957r877798_rule'
  tag stig_id: 'TSS0-ES-000840'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-25618r516271_fix'
  tag 'documentable'
  tag legacy: ['SV-107725', 'V-98621']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
