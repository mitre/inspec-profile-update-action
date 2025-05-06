control 'SV-237191' do
  title 'ColdFusion must transmit only encrypted representations of passwords for Flex Integration.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.  If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

ColdFusion offers RMI communication between Flex and ColdFusion.  The communication between the two will require authentication data.  When authentication data is transmitted, the data must be encrypted to protect it from discovery.  This can be done by enabling RMI over SSL within the Administrator Console.'
  desc 'check', 'Within the Administrator Console, navigate to the "Flex Integration" page under the "Data & Services" menu.  Ask the administrator if Flex is being used and if user credentials are being used for authentication.

If user credentials are being used for Flex authentication to ColdFusion and "Enable RMI over SSL for Data Management" is not checked, this is a finding.'
  desc 'fix', 'Navigate to the "Flex Integration" page under the "Data & Services" menu.  Check "Enable RMI over SSL for Data Management" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40410r641666_chk'
  tag severity: 'medium'
  tag gid: 'V-237191'
  tag rid: 'SV-237191r641668_rule'
  tag stig_id: 'CF11-04-000133'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-40373r641667_fix'
  tag 'documentable'
  tag legacy: ['SV-76945', 'V-62455']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
