control 'SV-90789' do
  title 'The OS X system must restrict the ability of individuals to use USB storage devices.'
  desc 'External hard drives, such as USB, must be disabled for users. USB hard drives are a potential vector for malware and can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.'
  desc 'check', 'If an approved HBSS DCM/DLP solution is installed, this is not applicable.

To verify external USB drives are disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 3 harddisk-external

If the option "eject,alert" is not set for "harddisk-external", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76101'
  tag rid: 'SV-90789r1_rule'
  tag stig_id: 'AOSX-12-000850'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
