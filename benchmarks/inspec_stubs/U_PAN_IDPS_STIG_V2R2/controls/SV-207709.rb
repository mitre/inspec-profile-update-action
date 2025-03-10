control 'SV-207709' do
  title 'The Palo Alto Networks security platform must continuously monitor inbound communications traffic for unusual/unauthorized activities or conditions.'
  desc "If inbound communications traffic is not continuously monitored for unusual/unauthorized activities or conditions, there will be times when hostile activity may not be noticed and defended against.

Although some of the components in the site's content scanning solution may be used for periodic scanning assessment, the IDPS sensors and other components must provide continuous, 24 hours a day, 7 days a week monitoring.

Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, use of unusual protocols and ports, and communications with suspected or known malicious external entities."
  desc 'check', 'Obtain the network architecture diagrams and identify where traffic crosses from one internal zone to another and review the configuration of the Palo Alto Networks security platform.  
The specific security policy is based on the authorized endpoints, applications, and protocols.

If it does not filter traffic passing between zones, this is a finding.'
  desc 'fix', 'The network architecture diagrams must identify where traffic crosses from one internal zone to another. The specific security policy is based on the authorized endpoints, applications, and protocols.

To create or edit a Security Policy:
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7963r358460_chk'
  tag severity: 'medium'
  tag gid: 'V-207709'
  tag rid: 'SV-207709r557390_rule'
  tag stig_id: 'PANW-IP-000049'
  tag gtitle: 'SRG-NET-000390-IDPS-00212'
  tag fix_id: 'F-7963r358461_fix'
  tag 'documentable'
  tag legacy: ['SV-77179', 'V-62689']
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
