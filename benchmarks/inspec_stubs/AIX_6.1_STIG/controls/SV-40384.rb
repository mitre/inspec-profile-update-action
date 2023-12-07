control 'SV-40384' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Determine the mode of the ntp.conf file.

# ls -l /etc/ntp.conf

If the mode is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the ntp.conf file to 0640 or less permissive.

# chmod 0640 /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39249r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22296'
  tag rid: 'SV-40384r1_rule'
  tag stig_id: 'GEN000252'
  tag gtitle: 'GEN000252'
  tag fix_id: 'F-34357r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
