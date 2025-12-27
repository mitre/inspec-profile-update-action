control 'SV-216241' do
  title 'The audit system must identify in which zone an event occurred.'
  desc 'Tracking the specific Solaris zones in the audit trail reduces the time required to determine the cause of a security event.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

List the non-global zones on the system.

# zoneadm list -vi | grep -v global

The Audit Configuration profile is required.

Determine whether the "zonename" auditing policy is in effect.

# pfexec auditconfig -getpolicy | grep active | grep zonename

If no output is returned, this is a finding.'
  desc 'fix', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

List the non-global zones on the system.

# zoneadm list -vi | grep -v global

The Audit Configuration profile is required.

Enable the "zonename" auditing policy.

# pfexec auditconfig -setpolicy +zonename'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17479r373099_chk'
  tag severity: 'low'
  tag gid: 'V-216241'
  tag rid: 'SV-216241r603268_rule'
  tag stig_id: 'SOL-11.1-100040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17477r373100_fix'
  tag 'documentable'
  tag legacy: ['V-47839', 'SV-60713']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
