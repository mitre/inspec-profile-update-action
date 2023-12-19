control 'SV-68913' do
  title 'The ALG providing content filtering must detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.

To comply with this requirement, the ALG may be configured to detect services either directly or indirectly (i.e., by detecting traffic associated with a service). This requirement applies to gateways/firewalls that perform content inspection or have higher-layer proxy functionality.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG detects use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum.

If the ALG does not detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54667'
  tag rid: 'SV-68913r1_rule'
  tag stig_id: 'SRG-NET-000384-ALG-000136'
  tag gtitle: 'SRG-NET-000384-ALG-000136'
  tag fix_id: 'F-59523r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
