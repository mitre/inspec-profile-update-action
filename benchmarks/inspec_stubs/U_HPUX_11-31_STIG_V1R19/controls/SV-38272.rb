control 'SV-38272' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the ownership of the NTP configuration file.
# ls -lL /etc/ntp.conf

If the owner is not root, this is a finding.'
  desc 'fix', 'Change the owner of the NTP configuration file.
# chown root  /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36240r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22294'
  tag rid: 'SV-38272r1_rule'
  tag stig_id: 'GEN000250'
  tag gtitle: 'GEN000250'
  tag fix_id: 'F-31497r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
