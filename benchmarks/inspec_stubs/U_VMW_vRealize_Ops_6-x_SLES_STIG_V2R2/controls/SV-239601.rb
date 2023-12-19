control 'SV-239601' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be owned by root.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. If the configuration files controlling time synchronization are not owned by a system account, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the ownership of the NTP configuration file:

# ls -l /etc/ntp.conf

If the owner is not "root", this is a finding.'
  desc 'fix', 'Change the owner of the NTP configuration file to "root":

# chown root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42834r662252_chk'
  tag severity: 'medium'
  tag gid: 'V-239601'
  tag rid: 'SV-239601r877038_rule'
  tag stig_id: 'VROM-SL-001090'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-42793r662253_fix'
  tag 'documentable'
  tag legacy: ['SV-99323', 'V-88673']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
