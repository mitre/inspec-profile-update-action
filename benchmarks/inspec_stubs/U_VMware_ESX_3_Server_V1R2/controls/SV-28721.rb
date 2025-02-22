control 'SV-28721' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be group-owned by root, bin, sys, or system.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system group, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the group-ownership of the NTP configuration file.

Procedure:
# ls -lL <configuration file>

If the group-owner is not root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the NTP configuration file.

Procedure:
# chgrp root <ntp.conf>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29016r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22295'
  tag rid: 'SV-28721r1_rule'
  tag stig_id: 'GEN000251'
  tag gtitle: 'GEN000251'
  tag fix_id: 'F-26026r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
