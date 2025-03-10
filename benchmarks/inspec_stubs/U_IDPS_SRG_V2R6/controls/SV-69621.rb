control 'SV-69621' do
  title 'The IDPS must detect network services that have not been authorized or approved by the ISSO or ISSM, at a minimum.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services. 

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.

To comply with this requirement, the IDPS may be configured to detect services either directly or indirectly (i.e., by detecting traffic associated with a service).'
  desc 'check', 'Verify the IDPS detects network services that have not been authorized or approved by the ISSO or ISSM, at a minimum.

If the IDPS does not detect network services that have not been authorized or approved by the ISSO or ISSM, at a minimum, this is a finding.'
  desc 'fix', 'Configure the IDPS to detect network services that have not been authorized or approved by the ISSO or ISSM, at a minimum.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55991r3_chk'
  tag severity: 'medium'
  tag gid: 'V-55375'
  tag rid: 'SV-69621r2_rule'
  tag stig_id: 'SRG-NET-000384-IDPS-00209'
  tag gtitle: 'SRG-NET-000384-IDPS-00209'
  tag fix_id: 'F-60241r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
