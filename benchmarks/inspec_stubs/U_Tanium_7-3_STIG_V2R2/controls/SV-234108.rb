control 'SV-234108' do
  title 'Tanium Server files must be excluded from on-access antivirus actions.'
  desc 'Similar to any other host-based applications, the Tanium Server is subject to the restrictions other System-level software may place on an operating environment. Antivirus, IPS, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the antivirus software used on the Tanium Server.

Review the settings of the antivirus software.

Validate exclusions exist which exclude the Tanium program files from being scanned by antivirus on-access scans.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software solution to prevent on-access scanning of Tanium Server program files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37293r610824_chk'
  tag severity: 'medium'
  tag gid: 'V-234108'
  tag rid: 'SV-234108r612749_rule'
  tag stig_id: 'TANS-SV-000040'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37258r610825_fix'
  tag 'documentable'
  tag legacy: ['SV-102289', 'V-92187']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
