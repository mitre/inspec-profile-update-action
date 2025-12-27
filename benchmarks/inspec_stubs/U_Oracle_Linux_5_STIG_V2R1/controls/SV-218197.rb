control 'SV-218197' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the ownership of the NTP configuration file.
# ls -l /etc/ntp.conf
If the owner is not root, this is a finding.'
  desc 'fix', 'Change the owner of the NTP configuration file.
# chown root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19672r568528_chk'
  tag severity: 'medium'
  tag gid: 'V-218197'
  tag rid: 'SV-218197r603259_rule'
  tag stig_id: 'GEN000250'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19670r568529_fix'
  tag 'documentable'
  tag legacy: ['V-22294', 'SV-63161']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
