control 'SV-69627' do
  title 'The IDPS must continuously monitor inbound communications traffic for unusual/unauthorized activities or conditions.'
  desc "If inbound communications traffic is not continuously monitored for unusual/unauthorized activities or conditions, there will be times when hostile activity may not be noticed and defended against. 

Although some of the components in the site's content scanning solution may be used for periodic scanning assessment, the IDPS sensors and other components must provide continuous, 24 hours a day, 7 days a week monitoring. 

Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, use of unusual protocols and ports, and communications with suspected or known malicious external entities."
  desc 'check', 'Verify the IDPS continuously monitors inbound communications traffic for unusual/unauthorized activities or conditions.

If the IDPS does not continuously monitor inbound communications traffic for unusual/unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'Configure the IDPS to continuously monitor inbound communications traffic for unusual/unauthorized activities or conditions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55997r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55381'
  tag rid: 'SV-69627r1_rule'
  tag stig_id: 'SRG-NET-000390-IDPS-00212'
  tag gtitle: 'SRG-NET-000390-IDPS-00212'
  tag fix_id: 'F-60247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
