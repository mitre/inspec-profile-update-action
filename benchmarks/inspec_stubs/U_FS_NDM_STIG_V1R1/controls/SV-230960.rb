control 'SV-230960' do
  title 'Forescout must disable the Request Customer Verification setting.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

This option connects to a user verification server at Forescout infrastructure used for verification of customer profiles and must not be used in DoD. If accidentally checked, this must error out.'
  desc 'check', 'In the Password and Sessions login options, ensure "request customer verification" is not enabled.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Ensure the option for "request customer verification" is unchecked.

If the Request Customer Verification setting is enabled, this is a finding.'
  desc 'fix', 'In the Password and Sessions login options, disable the "request customer verification" option.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Ensure the option for "request customer verification" is unchecked.'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33890r603719_chk'
  tag severity: 'low'
  tag gid: 'V-230960'
  tag rid: 'SV-230960r615886_rule'
  tag stig_id: 'FORE-NM-000340'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-33863r603720_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
