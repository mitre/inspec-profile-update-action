control 'SV-221252' do
  title 'Exchange Sender Identification Framework must be enabled.'
  desc 'Email is only as secure as the recipient. When the recipient is an email server accepting inbound messages, authenticating the sender enables the receiver to better assess message quality and to validate the sending domain as authentic. One or more authentication techniques used in combination can be effective in reducing spam, phishing, and forger attacks. 

The Sender ID Framework (SIDF) receiver accesses specially formatted DNS records (SPF format) that contain the IP address of authorized sending servers for the sending domain that can be compared to data in the email message header. Receivers are able to validate the authenticity of the sending domain, helping to avoid receiving inbound messages from phishing or other spam domains.'
  desc 'check', 'Note: If third-party anti-spam product is being used, the anti-spam product must be configured to meet the requirement.

Open the Exchange Management Shell and enter the following command:

Get-SenderIdConfig | Select Name, Identity, Enabled

If the value of "Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderIdConfig -Enable $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22967r411882_chk'
  tag severity: 'medium'
  tag gid: 'V-221252'
  tag rid: 'SV-221252r612603_rule'
  tag stig_id: 'EX16-ED-000560'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22956r411883_fix'
  tag 'documentable'
  tag legacy: ['SV-95295', 'V-80585']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
