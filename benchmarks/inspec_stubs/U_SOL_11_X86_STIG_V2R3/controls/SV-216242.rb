control 'SV-216242' do
  title 'The audit system must maintain a central audit trail for all zones.'
  desc 'Centralized auditing simplifies the investigative process to determine the cause of a security event.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

List the non-global zones on the system.

# zoneadm list -vi | grep -v global

The Audit Configuration profile is required.

Determine whether the "perzone" auditing policy is in effect.

# pfexec auditconfig -getpolicy | grep active | grep perzone

If output is returned, this is a finding.'
  desc 'fix', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

List the non-global zones on the system.

# zoneadm list -vi | grep -v global

The Audit Configuration profile is required.

Disable the "perzone" auditing policy.

# pfexec auditconfig -setpolicy -perzone'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17480r373102_chk'
  tag severity: 'low'
  tag gid: 'V-216242'
  tag rid: 'SV-216242r603268_rule'
  tag stig_id: 'SOL-11.1-100050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17478r373103_fix'
  tag 'documentable'
  tag legacy: ['V-47837', 'SV-60711']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
