control 'SV-69623' do
  title 'The IDPS must generate a log record when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services. 

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.'
  desc 'check', 'Verify the IDPS generates a log record when unauthorized network services are detected. 

If the IDPS does not generate a log record when unauthorized network services are detected, this is a finding.'
  desc 'fix', 'Configure the IDPS to generate a log record when unauthorized network services are detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55377'
  tag rid: 'SV-69623r1_rule'
  tag stig_id: 'SRG-NET-000385-IDPS-00210'
  tag gtitle: 'SRG-NET-000385-IDPS-00210'
  tag fix_id: 'F-60243r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
