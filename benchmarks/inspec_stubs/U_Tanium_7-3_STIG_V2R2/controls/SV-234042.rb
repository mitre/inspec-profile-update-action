control 'SV-234042' do
  title 'Tanium endpoint files must be excluded from on-access antivirus actions.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other System-level software may place on an operating environment. That is to say that Antivirus, IPS, Encryption, or other security and management stack software may disallow the Client from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the antivirus used on the Tanium clients.

Review the settings of the antivirus software.

Validate exclusions exist which exclude the Tanium program files from being scanned by antivirus on-access scans.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software solution to exclude the on-access scanning of Tanium client program files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37227r610626_chk'
  tag severity: 'medium'
  tag gid: 'V-234042'
  tag rid: 'SV-234042r612749_rule'
  tag stig_id: 'TANS-CL-000008'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37192r610627_fix'
  tag 'documentable'
  tag legacy: ['SV-102157', 'V-92055']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
