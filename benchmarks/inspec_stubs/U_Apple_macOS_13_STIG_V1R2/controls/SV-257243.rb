control 'SV-257243' do
  title 'The macOS system must restrict the ability of individuals to use USB storage devices.'
  desc 'External writeable media devices must be disabled for users. External USB devices are a potential vector for malware and can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.'
  desc 'check', 'Verify the macOS system is configured to disable USB storage devices with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 32 "mount-controls"

bd = (
"read-only"
);
blankbd = (
deny,
eject
);
blankcd = (
deny,
eject
);
blankdvd = (
deny,
eject
);
cd = (
"read-only"
);
"disk-image" = (
"read-only"
);
dvd = (
"read-only"
);
dvdram = (
deny,
eject
);
"harddisk-external" = (
deny,
eject
);

If the result does not match the output above and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable USB storage devices by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60928r905360_chk'
  tag severity: 'medium'
  tag gid: 'V-257243'
  tag rid: 'SV-257243r905362_rule'
  tag stig_id: 'APPL-13-005051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60869r905361_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
