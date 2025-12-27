control 'SV-89489' do
  title 'The MQ Appliance SSH interface to the messaging server must prohibit the use of cached authenticators after 600 seconds.'
  desc 'When the messaging server is using PKI authentication, a local revocation cache must be stored for instances when the revocation cannot be authenticated through the network, but if cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'In the MQ Appliance WebGUI, Go to Administration (gear icon) >> Access >> RBM Settings.

Verify that cache setting is defined and specifies "600" seconds.

If the time period is not set to "600" seconds, this is a finding.'
  desc 'fix', 'In the MQ Appliance WebGUI, Go to Administration (gear icon) >> Access >> RBM Settings.

Limit cache settings to "600" seconds.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74815'
  tag rid: 'SV-89489r1_rule'
  tag stig_id: 'MQMH-AS-000730'
  tag gtitle: 'SRG-APP-000400-AS-000246'
  tag fix_id: 'F-81431r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
