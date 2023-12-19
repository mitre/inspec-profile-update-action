control 'SV-218199' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.  If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the mode for the NTP configuration file is not more permissive than 0640.
# ls -l /etc/ntp.conf

If the mode is more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the NTP configuration file to 0640 or more restrictive.
# chmod 0640 /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19674r568534_chk'
  tag severity: 'medium'
  tag gid: 'V-218199'
  tag rid: 'SV-218199r603259_rule'
  tag stig_id: 'GEN000252'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19672r568535_fix'
  tag 'documentable'
  tag legacy: ['V-22296', 'SV-63171']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
