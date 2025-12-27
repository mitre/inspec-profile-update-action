control 'SV-26292' do
  title 'The system clock must be synchronized continuously.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  Internal system clocks tend to drift and require periodic resynchronization to ensure their accuracy.  Software, such as ntpd, can be used to continuously synchronize the system clock with authoritative sources.  Alternatively, the system may be synchronized periodically, with a maximum of one day between synchronizations.

If the system is completely isolated (i.e., it has no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'fix', 'Enable the NTP daemon for continuous synchronization.
# service ntpd start ; chkconfig ntpd on

Edit the "/etc/ntp.conf" file and add or update an entry to define "maxpoll" to "10".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22290'
  tag rid: 'SV-26292r4_rule'
  tag stig_id: 'GEN000241'
  tag gtitle: 'GEN000241'
  tag fix_id: 'F-23444r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
