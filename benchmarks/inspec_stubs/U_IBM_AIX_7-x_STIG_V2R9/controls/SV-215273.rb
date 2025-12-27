control 'SV-215273' do
  title 'AIX time synchronization configuration file must be group-owned by bin, or system.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. If the configuration files controlling time synchronization are not owned by a system group, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check "/etc/ntp.conf" file group ownership:
# ls -al /etc/ntp.conf

The above command should yield the following output:
-rw-r-----    1 root     system          993 Aug 25 18:26 /etc/ntp.conf

If the file is not group-owned by "system", this is a finding.'
  desc 'fix', 'Change the group owner of the files in "/etc/news" to "system" using:
# chgrp system /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16471r294270_chk'
  tag severity: 'medium'
  tag gid: 'V-215273'
  tag rid: 'SV-215273r508663_rule'
  tag stig_id: 'AIX7-00-002082'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16469r294271_fix'
  tag 'documentable'
  tag legacy: ['SV-101701', 'V-91603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
