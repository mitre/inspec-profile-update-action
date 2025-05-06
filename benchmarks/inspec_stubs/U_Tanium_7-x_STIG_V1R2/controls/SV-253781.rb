control 'SV-253781' do
  title 'Tanium Client processes must be excluded from On-Access scan.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other system-level software may place on an operating environment. Antivirus, intrusion prevention system (IPS), encryption, or other security and management stack software may disallow the Client from working as expected.

For more information, refer to https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/security_exceptions.html?Highlight=exclusion.'
  desc 'check', 'Review the settings of the antivirus software.

Verify exclusions exist that exclude the Tanium Client process interactions from On-Access scans and are treated as Low-Risk.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'Implement exclusion policies within the antivirus software to exclude the On-Access scanning of Tanium Client process interactions. These processes should be treated as Low-Risk and not scanned during read or write events.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57233r842369_chk'
  tag severity: 'medium'
  tag gid: 'V-253781'
  tag rid: 'SV-253781r842371_rule'
  tag stig_id: 'TANS-00-001055'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-57184r842370_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
