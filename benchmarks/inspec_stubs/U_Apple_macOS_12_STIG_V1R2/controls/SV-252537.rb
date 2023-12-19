control 'SV-252537' do
  title 'The macOS system must restrict the ability of individuals to use USB storage devices.'
  desc 'External writeable media devices must be disabled for users. External USB devices are a potential vector for malware and can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.

'
  desc 'check', %q(Verify the system is configured to disable USB storage devices:

$ /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/egrep -A 3 'blankbd|blankcd|blankdvd|disk-image|dvdram|harddisk-external'

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

“disk-image" = (
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

If the result does not match the output above, this is a finding.)
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55993r816423_chk'
  tag severity: 'medium'
  tag gid: 'V-252537'
  tag rid: 'SV-252537r816425_rule'
  tag stig_id: 'APPL-12-005051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55943r816424_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000319-GPOS-00164']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001967']
  tag nist: ['CM-6 b', 'IA-3 (1)']
end
