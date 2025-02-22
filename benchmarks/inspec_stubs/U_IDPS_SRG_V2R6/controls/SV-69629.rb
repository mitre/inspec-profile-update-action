control 'SV-69629' do
  title 'The IDPS must continuously monitor outbound communications traffic for unusual/unauthorized activities or conditions.'
  desc "If outbound communications traffic is not continuously monitored for unusual/unauthorized activities or conditions, there will be times when hostile activity may not be noticed and defended against. 

Although some of the components in the site's content scanning solution may be used for periodic scanning assessment, the IDPS sensors and other components must provide continuous, 24 hours a day, 7 days a week monitoring.

Unusual/unauthorized activities or conditions related to information system outbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, use of unusual protocols and ports, and communications with suspected or known malicious external entities."
  desc 'check', 'Verify the IDPS continuously monitors outbound communications traffic for unusual/unauthorized activities or conditions.

If the IDPS does not continuously monitor outbound communications traffic for unusual/unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'Configure the IDPS to continuously monitor outbound communications traffic for unusual/unauthorized activities or conditions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55383'
  tag rid: 'SV-69629r1_rule'
  tag stig_id: 'SRG-NET-000391-IDPS-00213'
  tag gtitle: 'SRG-NET-000391-IDPS-00213'
  tag fix_id: 'F-60249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002662']
  tag nist: ['SI-4 (4) (b)']
end
