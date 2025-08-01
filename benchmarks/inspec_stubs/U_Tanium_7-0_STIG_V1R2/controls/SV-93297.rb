control 'SV-93297' do
  title 'Tanium endpoint files must be excluded from on-access antivirus actions.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other System-level software may place on an operating environment. That is to say that Antivirus, IPS, Encryption, or other security and management stack software may disallow the Client from working as expected.

https://docs.tanium.com/platform_install/platform_install/reference_host_system_security_exceptions.html.'
  desc 'check', 'Consult with the Tanium System Administrator to determine the antivirus used on the Tanium clients.

Review the settings of the antivirus software.

Validate exclusions exist that exclude the Tanium program files from being scanned by antivirus on-access scans.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software solution to exclude the on-access scanning of Tanium client program files.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78591'
  tag rid: 'SV-93297r1_rule'
  tag stig_id: 'TANS-CL-000008'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-85327r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
