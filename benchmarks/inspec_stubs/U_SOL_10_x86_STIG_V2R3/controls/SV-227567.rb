control 'SV-227567' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must not have an extended ACL.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check for an extended ACL on the NTP configuration file.
# ls -l /etc/inet/ntp.conf
If the permissions contain a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/inet/ntp.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29729r488237_chk'
  tag severity: 'medium'
  tag gid: 'V-227567'
  tag rid: 'SV-227567r603266_rule'
  tag stig_id: 'GEN000253'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29717r488238_fix'
  tag 'documentable'
  tag legacy: ['V-22297', 'SV-26301']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
