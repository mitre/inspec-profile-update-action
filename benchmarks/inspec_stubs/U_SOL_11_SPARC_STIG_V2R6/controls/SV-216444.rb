control 'SV-216444' do
  title 'Address Space Layout Randomization (ASLR) must be enabled.'
  desc 'Modification of memory area can result in executable code vulnerabilities. ASLR can reduce the likelihood of these attacks. ASLR activates the randomization of key areas of the process such as stack, brk-based heap, memory mappings, and so forth.'
  desc 'check', 'This check applies to the global zone only. 

Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine if address space layout randomization is enabled.

Determine the OS version you are currently securing:. 
# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# sxadm info -p | grep aslr | grep enabled

For Solaris 11.4 or newer:
# sxadm status -p -o status aslr | grep enabled 

If no output is produced, this is a finding.'
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Enable address space layout randomization.

# sxadm delcust aslr

Enabling ASLR may affect the function or stability of some applications, including those that use Solaris Intimate Shared Memory features.'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17680r371420_chk'
  tag severity: 'low'
  tag gid: 'V-216444'
  tag rid: 'SV-216444r603267_rule'
  tag stig_id: 'SOL-11.1-080030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17678r371421_fix'
  tag 'documentable'
  tag legacy: ['SV-60895', 'V-48023']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
