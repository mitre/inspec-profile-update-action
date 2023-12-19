control 'SV-38273' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be group-owned by root, bin, sys, or system.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system group, unauthorized modifications could result in the failure of time synchronization.'
  desc 'fix', 'Change the group-owner of the NTP configuration file.

Procedure:
# chgrp root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22295'
  tag rid: 'SV-38273r1_rule'
  tag stig_id: 'GEN000251'
  tag gtitle: 'GEN000251'
  tag fix_id: 'F-31498r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
