control 'SV-204792' do
  title 'The application server must compare internal application server clocks at least every 24 hours with an authoritative time source.'
  desc 'Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.'
  desc 'check', 'Review application server documentation and confirm that the application server compares internal application server clocks at least every 24 hours with an authoritative time source.

If the application server does not compare internal application server clocks to an authoritative source or if the frequency is greater than every 24 hours, this is a finding.'
  desc 'fix', 'Configure the application server to compare internal application server clocks at least every 24 hours with an authoritative time source.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4912r283023_chk'
  tag severity: 'medium'
  tag gid: 'V-204792'
  tag rid: 'SV-204792r508029_rule'
  tag stig_id: 'SRG-APP-000371-AS-000077'
  tag gtitle: 'SRG-APP-000371'
  tag fix_id: 'F-4912r283024_fix'
  tag 'documentable'
  tag legacy: ['SV-71707', 'V-57435']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
