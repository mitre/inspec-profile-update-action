control 'SV-250321' do
  title 'The macOS system must restrict the ability to utilize external writable media devices.'
  desc 'External writeable media devices must be disabled for users. External USB devices are a potential vector for malware and can be used to exfiltrate sensitive data.'
  desc 'check', %q(Verify the system is configured to disable external writable media devices:
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
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-53756r832918_chk'
  tag severity: 'medium'
  tag gid: 'V-250321'
  tag rid: 'SV-250321r832919_rule'
  tag stig_id: 'AOSX-15-005051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-53710r802397_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
