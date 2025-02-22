control 'SV-32521' do
  title 'The system clock must be synchronized continuously, or at least daily.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  Internal system clocks tend to drift and require periodic resynchronization to ensure their accuracy.  Software, such as ntpd, can be used to continuously synchronize the system clock with authoritative sources.  Alternatively, the system may be synchronized periodically, with a maximum of one day between synchronizations.

If the system is completely isolated (that is, it has no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', "Check the system's configuration to determine if the NTP daemon is running continuously, or if a scheduled job is configured to synchronize time at least every hour.  If the NTP daemon is not running, and there is no scheduled job for time synchronization, this is a finding."
  desc 'fix', 'Configure the system to synchronize time continuously or schedule a job to perform time synchronization at least once per hour.  Consult system documentation for implementation details.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-32829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22290'
  tag rid: 'SV-32521r1_rule'
  tag stig_id: 'GEN000241'
  tag gtitle: 'GEN000241'
  tag fix_id: 'F-28940r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
