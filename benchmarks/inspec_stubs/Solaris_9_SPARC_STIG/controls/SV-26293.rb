control 'SV-26293' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'fix', 'Change the owner of the NTP configuration file to root.
# chown root /etc/inet/ntp.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22294'
  tag rid: 'SV-26293r1_rule'
  tag stig_id: 'GEN000250'
  tag gtitle: 'GEN000250'
  tag fix_id: 'F-23445r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
