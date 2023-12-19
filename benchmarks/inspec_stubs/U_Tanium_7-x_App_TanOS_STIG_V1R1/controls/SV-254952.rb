control 'SV-254952' do
  title 'Tanium Client processes must be excluded from on-access scan.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other system-level software may place on an operating environment. That is to say that Antivirus, IPS, Encryption, or other security and management stack software may disallow the Client from working as expected.

https://docs.tanium.com/client/client/requirements.html#Host_system_security_exceptions'
  desc 'check', 'Review the settings of the antivirus software.

Validate exclusions exist that exclude the Tanium Client process interactions from on-access scans and are treated as low-risk.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software solution to exclude the on-access scanning of Tanium Client process interactions. These processes should be treated as low-risk and not scanned during read or write events.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58565r867754_chk'
  tag severity: 'medium'
  tag gid: 'V-254952'
  tag rid: 'SV-254952r867756_rule'
  tag stig_id: 'TANS-AP-001410'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-58509r867755_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
