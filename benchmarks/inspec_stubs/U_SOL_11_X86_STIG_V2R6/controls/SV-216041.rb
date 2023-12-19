control 'SV-216041' do
  title 'The operating system must shut down by default upon audit failure (unless availability is an overriding concern).'
  desc 'Continuing to operate a system without auditing working properly can result in undocumented access or system changes.'
  desc 'check', 'The Audit Configuration profile is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

# pfexec auditconfig -getpolicy | grep ahlt

If the output does not include "ahlt" as an active audit policy, this is a finding.

# pfexec auditconfig -getpolicy | grep active | grep cnt

If the output includes "cnt" as an active audit policy, this is a finding.'
  desc 'fix', 'The Audit Configuration profile is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Set audit policy to halt and suspend on failure.

# pfexec auditconfig -setpolicy +ahlt
# pfexec auditconfig -setpolicy -cnt'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17279r372505_chk'
  tag severity: 'medium'
  tag gid: 'V-216041'
  tag rid: 'SV-216041r603268_rule'
  tag stig_id: 'SOL-11.1-010420'
  tag gtitle: 'SRG-OS-000047'
  tag fix_id: 'F-17277r372506_fix'
  tag 'documentable'
  tag legacy: ['V-47863', 'SV-60737']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
