control 'SV-250320' do
  title 'The macOS system must restrict the ability to utilize external writeable media devices.'
  desc 'External writeable media devices must be disabled for users. External USB devices are a potential vector for malware and can be used to exfiltrate sensitive data.'
  desc 'check', %q(Verify the system is configured to disable external writeable media devices:
$ /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/egrep -A 3 'blankbd|blankcd|blankdvd|dvdram|harddisk-external'

“blankbd" = (
deny,
eject
);

“blankcd" = (
deny,
eject
);

“blankdvd" = (
deny,
eject
);

“dvdram" = (
deny,
eject
);

“harddisk-external" = (
deny,
eject
);

If the result does not match the output above and the external writeable media devices have not been approved by the Authorizing Official, this is a finding.)
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-53755r818790_chk'
  tag severity: 'medium'
  tag gid: 'V-250320'
  tag rid: 'SV-250320r818791_rule'
  tag stig_id: 'APPL-11-005051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-53709r802394_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
