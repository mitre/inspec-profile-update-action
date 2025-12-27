control 'SV-252539' do
  title 'The macOS system must restrict the ability of individuals to write to external optical media.'
  desc 'External writeable media devices must be disabled for users. External optical media devices can be used to exfiltrate sensitive data if an approved data-loss prevention (DLP) solution is not installed.'
  desc 'check', "Verify the system is configured to disable writing to external optical media devices:

$ /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep 'BurnSupport'

BurnSupport = off;

If the command does not return a line, this is a finding.
If 'BurnSupport' is set to a value other than 'off' and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding."
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55995r816429_chk'
  tag severity: 'low'
  tag gid: 'V-252539'
  tag rid: 'SV-252539r816431_rule'
  tag stig_id: 'APPL-12-005053'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55945r816430_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
