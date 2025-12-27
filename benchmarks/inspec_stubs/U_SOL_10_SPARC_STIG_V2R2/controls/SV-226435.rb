control 'SV-226435' do
  title 'The system clock must be synchronized continuously.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  Internal system clocks tend to drift and require periodic resynchronization to ensure their accuracy.  Software, such as NTPD, can be used to continuously synchronize the system clock with authoritative sources.  Alternatively, the system may be synchronized periodically, with a maximum of one day between synchronizations.

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'NTP must be used and used only in the global zone.  Determine the type of zone that you are currently securing.

# zonename

If the command output is not "global", then NTP must be disabled.  Check the system for a running NTP daemon.

# svcs -Ho state ntp

If NTP is online, this is a finding.

If the output from "zonename" is "global", then NTP must be enabled.  Check the system for a running NTP daemon.

# svcs -Ho state ntp

If NTP is not online, this is a finding.'
  desc 'fix', 'Determine the type of zone that you are currently securing.

# zonename

If the command output is not "global", then NTP must be disabled.

# svcadm disable ntp

If the output from "zonename" is "global", then NTP must be enabled.  

# svcadm enable ntp'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28596r482669_chk'
  tag severity: 'medium'
  tag gid: 'V-226435'
  tag rid: 'SV-226435r603265_rule'
  tag stig_id: 'GEN000241'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28584r482670_fix'
  tag 'documentable'
  tag legacy: ['V-22290', 'SV-26291']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
