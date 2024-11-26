control 'SV-79775' do
  title 'The DataPower Gateway providing content filtering must generate a log record when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.'
  desc 'check', 'Using the WebGUI, go to Network >> Management >> Web Management Service. Verify that the "WS-Management endpoint" checkbox is checked and that an IP and port for the WS-Management endpoint to connect to is configured.

If the WS-Management endpoint is not enabled (checked) or not configured, this is a finding.'
  desc 'fix', 'Using the WebGUI, go to Network >> Management >> Web Management Service. Check the "WS-Management endpoint" checkbox. Configure an IP and port for the WS-Management endpoint to connect to.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65285'
  tag rid: 'SV-79775r1_rule'
  tag stig_id: 'WSDP-AG-000109'
  tag gtitle: 'SRG-NET-000385-ALG-000137'
  tag fix_id: 'F-71225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
