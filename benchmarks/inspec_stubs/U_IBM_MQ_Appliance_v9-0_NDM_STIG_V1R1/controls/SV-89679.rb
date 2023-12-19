control 'SV-89679' do
  title 'The MQ Appliance network device must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators. 

If cached authentication information is out of date, the validity of the authentication information may be questionable. 

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP and the cache setting is defined and specifies the organization-defined time period. 

If the Authentication Method is not set to LDAP and the cache setting does not specify the organization-defined time period, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. Limit cache settings to an organization-defined time period. 

Configure other LDAP connection settings as required.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75005'
  tag rid: 'SV-89679r1_rule'
  tag stig_id: 'MQMH-ND-001240'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-81621r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
