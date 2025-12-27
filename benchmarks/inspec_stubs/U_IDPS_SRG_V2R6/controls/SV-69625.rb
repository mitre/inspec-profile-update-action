control 'SV-69625' do
  title 'The IDPS must generate an alert to the ISSM and ISSO, at a minimum, when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites).

The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSO to the vulnerability discussion.'
  desc 'check', 'Verify the IDPS generates an alert to the ISSM and ISSO, at a minimum, when unauthorized network services are detected.

If the IDPS does not generate an alert to the ISSM and ISSO, at a minimum, when unauthorized network services are detected, this is a finding.'
  desc 'fix', 'Configure the IDPS to generate an alert to the ISSM and ISSo, at a minimum, when unauthorized network services are detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55995r5_chk'
  tag severity: 'medium'
  tag gid: 'V-55379'
  tag rid: 'SV-69625r3_rule'
  tag stig_id: 'SRG-NET-000385-IDPS-00211'
  tag gtitle: 'SRG-NET-000385-IDPS-00211'
  tag fix_id: 'F-60245r4_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
