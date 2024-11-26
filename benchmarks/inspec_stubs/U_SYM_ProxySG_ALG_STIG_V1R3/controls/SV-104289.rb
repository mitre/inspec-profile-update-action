control 'SV-104289' do
  title 'Symantec ProxySG providing content filtering must detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice over Internet Protocol, Instant Messaging, auto-execute, and file sharing.

To comply with this requirement, the ALG may be configured to detect services either directly or indirectly (i.e., by detecting traffic associated with a service). This requirement applies to gateways/firewalls that perform content inspection or have higher-layer proxy functionality.

ProxySG is a default-deny device and only permits authorized/approved network services to be used.'
  desc 'check', 'Determine what network proxy services are enabled on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Review each service specified in the list with the ProxySG administrator to verify that all approved networks have been accounted for.

If Symantec ProxySG providing content filtering does not detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum, this is a finding.'
  desc 'fix', 'Enable network proxy services on the ProxySG.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Click "New Service".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93521r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94335'
  tag rid: 'SV-104289r1_rule'
  tag stig_id: 'SYMP-AG-000610'
  tag gtitle: 'SRG-NET-000384-ALG-000136'
  tag fix_id: 'F-100451r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
