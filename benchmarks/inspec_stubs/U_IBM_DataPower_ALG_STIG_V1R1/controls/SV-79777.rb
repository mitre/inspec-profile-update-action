control 'SV-79777' do
  title 'The DataPower Gateway providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore, may be unreliable or serve as malicious rogues for valid services.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites). The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.'
  desc 'check', 'Using the WebGUI, go to Network >> Management >> Web Management Service. The "WS-Management endpoint" checkbox should be checked. Verify an IP and port for the WS-Management endpoint to connect to.

If the WS-Management endpoint is not enabled (checked) or not configured, this is a finding.'
  desc 'fix', 'Using the WebGUI, go to Network >> Management >> Web Management Service. Check the "WS-Management endpoint" checkbox. Configure an IP and port for the WS-Management endpoint to connect to.

Using the service monitoring data provided by the DataPower Gateway, the WS-Management endpoint would be responsible for detecting the use of unauthorized network services and then generating an alert.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65287'
  tag rid: 'SV-79777r1_rule'
  tag stig_id: 'WSDP-AG-000110'
  tag gtitle: 'SRG-NET-000385-ALG-000138'
  tag fix_id: 'F-71227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
