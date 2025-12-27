control 'SV-215335' do
  title 'AIX must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at AIX-level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).

The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Verification of white-listed software occurs prior to execution or at system startup.

This requirement applies to operating system programs, functions, and services designed to manage system processes and configurations (e.g., group policies).

'
  desc 'check', 'Run the following command to show the current status of the "TE" running on the system:
# trustchk -p

The above command should yield the following output:
TE=ON

If the output is "TE=OFF", this is a finding.'
  desc 'fix', 'Run the following command to turn on Trusted Execution:
# trustchk -p TE=ON'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16533r294456_chk'
  tag severity: 'medium'
  tag gid: 'V-215335'
  tag rid: 'SV-215335r508663_rule'
  tag stig_id: 'AIX7-00-003025'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-16531r294457_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-91535', 'SV-101633']
  tag cci: ['CCI-001764', 'CCI-001774']
  tag nist: ['CM-7 (2)', 'CM-7 (5) (b)']
end
