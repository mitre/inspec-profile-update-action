control 'SV-68917' do
  title 'The ALG providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore, may be unreliable or serve as malicious rogues for valid services.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites). The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG generates an alert to, at a minimum, the ISSO and ISSM when unauthorized network services are detected.

If the ALG does not generate an alert to, at a minimum, the ISSO and ISSM when unauthorized network services are detected, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to generate an alert to, at a minimum, the ISSO and ISSM when unauthorized network services are detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55291r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54671'
  tag rid: 'SV-68917r1_rule'
  tag stig_id: 'SRG-NET-000385-ALG-000138'
  tag gtitle: 'SRG-NET-000385-ALG-000138'
  tag fix_id: 'F-59527r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
