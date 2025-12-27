control 'SV-226439' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be group-owned by root, bin, or sys.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system group, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the group ownership of the NTP configuration file.

Procedure:
# ls -l /etc/inet/ntp.conf

If the group owner is not root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the NTP configuration file.

Procedure:
# chgrp root /etc/inet/ntp.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28600r482681_chk'
  tag severity: 'medium'
  tag gid: 'V-226439'
  tag rid: 'SV-226439r603265_rule'
  tag stig_id: 'GEN000251'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28588r482682_fix'
  tag 'documentable'
  tag legacy: ['V-22295', 'SV-26296']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
