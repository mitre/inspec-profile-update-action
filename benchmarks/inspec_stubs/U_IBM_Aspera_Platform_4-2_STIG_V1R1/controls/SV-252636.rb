control 'SV-252636' do
  title 'The IBM Aspera High-Speed Transfer Server must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Network element management includes the ability to control the number of users and user sessions that utilize a network element. Limiting the number of current sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be the same as the requirements specified for the application for which it serves as intermediary.

This policy only applies to application gateways/firewalls (e.g., identity management or authentication gateways) that provide user account services as part of the intermediary services.

The number of incoming transfer requests to the IBM Aspera High-Speed Transfer Server permitted via a POST to the REST service can be limited by the setting of "transfer_manager_max_concurrent_sessions" in The IBM Aspera.conf.'
  desc 'check', 'Verify the IBM Aspera High-Speed Transfer Server limits the number of concurrent sessions to an organization-defined number for all accounts and/or account types with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep concurrent

transfer_manager_max_concurrent_sessions: "20"

If the value returned (in this example 20 is the default) is not the organization-defined number, this is a finding.'
  desc 'fix', 'Configure the IBM Aspera High-Speed Transfer Server to limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types with the following command:

$ sudo /opt/aspera/bin/asconfiguration -x "set_server_data; transfer_manager_max_concurrent_sessions,<insertorganizationvaluehere>"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56092r818076_chk'
  tag severity: 'medium'
  tag gid: 'V-252636'
  tag rid: 'SV-252636r818078_rule'
  tag stig_id: 'ASP4-TS-020200'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag fix_id: 'F-56042r818077_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
