control 'SV-89665' do
  title 'The MQ Appliance network device must notify the administrator, upon successful logon (access), of the location of last logon (terminal or IP address) in addition to the result, date and time of the last logon (access).'
  desc 'Administrators need to be aware of activity that occurs regarding their account. Providing them with information deemed important by the organization may aid in the discovery of unauthorized access or thwart a potential attacker. 

Organizations should consider the risks to the specific information system being accessed and the threats presented by the device to the environment when configuring this option. An excessive or unnecessary amount of information presented to the administrator at logon is not recommended.

MQ provides logon information including date, time and source IP information in event logs. A third party log monitoring solution that monitors the logs for unsuccessful logons and corresponding date, time and location information must be utilized to provide the notification.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. Request third-party log monitoring alarming information that provides the notification alerts regarding logons, dates, times, and source IP addresses.

If it is not set to LDAP and third-party alarming notifications are not used, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. Configure LDAP connection as required.

Configure notification alerts in third party event notification solution.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74991'
  tag rid: 'SV-89665r1_rule'
  tag stig_id: 'MQMH-ND-001010'
  tag gtitle: 'SRG-APP-000346-NDM-000291'
  tag fix_id: 'F-81607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002250']
  tag nist: ['CM-6 b', 'AC-9 (4)']
end
