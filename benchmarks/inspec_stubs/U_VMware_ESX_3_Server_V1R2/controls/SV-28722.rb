control 'SV-28722' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Verify the mode for the NTP configuration file is not more permissive than 0640.
# ls -l ntp.conf

If the mode is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the NTP configuration file to 0640 or less permissive.
# chmod 0640 ntp.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29017r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22296'
  tag rid: 'SV-28722r1_rule'
  tag stig_id: 'GEN000252'
  tag gtitle: 'GEN000252'
  tag fix_id: 'F-26027r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
