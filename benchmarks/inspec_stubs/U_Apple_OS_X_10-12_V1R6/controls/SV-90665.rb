control 'SV-90665' do
  title 'The OS X system must be configured with automatic actions disabled for picture CDs.'
  desc 'Applications should not be configured to launch automatically when a disk is inserted. This potentially circumvents anti-virus software and allows malicious users to craft disks that can exploit user applications. Disabling Automatic Actions for picture CDs mitigates this risk.'
  desc 'check', %q(If an approved HBSS DCM/DLP solution is installed, this is not applicable.

To check if the system has the correct setting for picture CDs in the configuration profile, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 2 'com.apple.digihub.cd.picture.appeared'

If this is not defined or "action" is not set to "1", this is a finding.)
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75977'
  tag rid: 'SV-90665r1_rule'
  tag stig_id: 'AOSX-12-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82615r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
