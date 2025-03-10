control 'SV-240507' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the ownership of the NTP configuration file:

# ls -l /etc/ntp.conf

If the owner is not "root", this is a finding.'
  desc 'fix', 'Change the owner of the NTP configuration file:

# chown root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43740r671260_chk'
  tag severity: 'medium'
  tag gid: 'V-240507'
  tag rid: 'SV-240507r877038_rule'
  tag stig_id: 'VRAU-SL-001115'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-43699r671261_fix'
  tag 'documentable'
  tag legacy: ['SV-100441', 'V-89791']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
