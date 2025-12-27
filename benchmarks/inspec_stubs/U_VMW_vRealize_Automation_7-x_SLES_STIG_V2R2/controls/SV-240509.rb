control 'SV-240509' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must have mode 0640 or less permissive.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. If the configuration files controlling time synchronization are not protected, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check that the mode for the NTP configuration file is not more permissive than "0640":

# ls -l /etc/ntp.conf

If the mode is more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the mode of the NTP configuration file to "0640" or less permissive:

# chmod 0640 /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43742r671266_chk'
  tag severity: 'medium'
  tag gid: 'V-240509'
  tag rid: 'SV-240509r877038_rule'
  tag stig_id: 'VRAU-SL-001125'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-43701r671267_fix'
  tag 'documentable'
  tag legacy: ['SV-100445', 'V-89795']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
