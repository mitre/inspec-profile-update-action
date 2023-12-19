control 'SV-252537' do
  title 'The macOS system must restrict the ability to utilize external writeable media devices.'
  desc 'External writeable media devices must be disabled for users. External USB devices are a potential vector for malware and can be used to exfiltrate sensitive data.

'
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
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55993r877368_chk'
  tag severity: 'medium'
  tag gid: 'V-252537'
  tag rid: 'SV-252537r877369_rule'
  tag stig_id: 'APPL-12-005051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55943r816424_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000319-GPOS-00164']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001967']
  tag nist: ['CM-6 b', 'IA-3 (1)']
end
