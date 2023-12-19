control 'SV-256566' do
  title 'The Photon operating system must be configured so that all cron paths are protected from unauthorized modification.'
  desc 'If cron files and folders are accessible to unauthorized users, malicious jobs may be created.'
  desc 'check', 'At the command line, run the following command:

# stat -c "%n permissions are %a and owned by %U:%G" /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly

Expected result:

/etc/cron.d permissions are 755 and owned by root:root
/etc/cron.daily permissions are 755 and owned by root:root
/etc/cron.hourly permissions are 755 and owned by root:root
/etc/cron.monthly permissions are 755 and owned by root:root
/etc/cron.weekly permissions are 755 and owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command line, run the following commands for each returned file:

# chmod 755 <path>
# chown root:root <path>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60241r887370_chk'
  tag severity: 'medium'
  tag gid: 'V-256566'
  tag rid: 'SV-256566r887372_rule'
  tag stig_id: 'PHTN-30-000097'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60184r887371_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
