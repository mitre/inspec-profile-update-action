control 'SV-81545' do
  title 'Tanium Server files must be protected from antivirus actions.'
  desc 'Similar to any other host-based applications, the Tanium Server is subject to the restrictions other System-level software may place on an operating environment. Antivirus, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://kb.tanium.com/Security_Software_Exceptions'
  desc 'check', 'Consult with the Tanium System Administrator to determine the antivirus software used on the Tanium Server.

Review the settings of the antivirus software.

Validate exclusions exist which exclude the Tanium program files from being scanned by antivirus.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software solution to exclude the scanning of Tanium program files.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67055'
  tag rid: 'SV-81545r1_rule'
  tag stig_id: 'TANS-SV-000040'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
