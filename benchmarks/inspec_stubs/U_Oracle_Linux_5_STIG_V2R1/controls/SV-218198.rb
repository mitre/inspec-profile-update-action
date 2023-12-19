control 'SV-218198' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be group-owned by root, bin, or sys.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system group, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the group ownership of the NTP configuration file.

Procedure:
# ls -lL /etc/ntp.conf

If the group owner is not root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the NTP configuration file.

Procedure:
# chgrp root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19673r568531_chk'
  tag severity: 'medium'
  tag gid: 'V-218198'
  tag rid: 'SV-218198r603259_rule'
  tag stig_id: 'GEN000251'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19671r568532_fix'
  tag 'documentable'
  tag legacy: ['V-22295', 'SV-63165']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
