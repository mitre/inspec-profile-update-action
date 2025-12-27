control 'SV-68915' do
  title 'The ALG providing content filtering must generate a log record when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG generates a log record when unauthorized network services are detected.

If the ALG does not generate a log record when unauthorized network services are detected, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to generate a log record when unauthorized network services are detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55289r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54669'
  tag rid: 'SV-68915r1_rule'
  tag stig_id: 'SRG-NET-000385-ALG-000137'
  tag gtitle: 'SRG-NET-000385-ALG-000137'
  tag fix_id: 'F-59525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
