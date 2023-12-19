control 'SV-240508' do
  title 'The time synchronization configuration file (such as /etc/ntp.conf) must be group-owned by root, bin, sys, or system.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised. If the configuration files controlling time synchronization are not owned by a system group, unauthorized modifications could result in the failure of time synchronization.'
  desc 'check', 'Check the group-ownership of the NTP configuration file:

# ls -lL /etc/ntp.conf

If the group-owner is not "root", "bin", "sys", or "system", this is a finding.'
  desc 'fix', 'Change the group-owner of the NTP configuration file:

# chgrp root /etc/ntp.conf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43741r671263_chk'
  tag severity: 'medium'
  tag gid: 'V-240508'
  tag rid: 'SV-240508r877038_rule'
  tag stig_id: 'VRAU-SL-001120'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-43700r671264_fix'
  tag 'documentable'
  tag legacy: ['SV-100443', 'V-89793']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
