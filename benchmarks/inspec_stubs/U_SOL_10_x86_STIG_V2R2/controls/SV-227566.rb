control 'SV-227566' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Verify the mode for the NTP configuration file is not more permissive than 0640.
# ls -l /etc/inet/ntp.conf

If the mode is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the NTP configuration file to 0640 or less permissive.
# chmod 0640 /etc/inet/ntp.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29728r488234_chk'
  tag severity: 'medium'
  tag gid: 'V-227566'
  tag rid: 'SV-227566r603266_rule'
  tag stig_id: 'GEN000252'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29716r488235_fix'
  tag 'documentable'
  tag legacy: ['V-22296', 'SV-26298']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
