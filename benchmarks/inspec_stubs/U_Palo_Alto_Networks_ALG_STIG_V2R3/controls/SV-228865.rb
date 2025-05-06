control 'SV-228865' do
  title 'The Palo Alto Networks security platform must detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.'
  desc 'check', 'Obtain the list of network services that have not been authorized or approved by the ISSM and ISSO.
For each prohibited network service, view the security policies that denies traffic associated with it and logs the denied traffic.

If there is no list of unauthorized network services, this is a finding.

If there are no configured security policies that specifically match the list of unauthorized network services, this is a finding.

If the security policies do not deny the traffic associated with the unauthorized network services, this is a finding.'
  desc 'fix', 'To create or edit a Security Policy:
Go to Policies >> Security
Select "Add" to create a new security policy, or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31100r513890_chk'
  tag severity: 'medium'
  tag gid: 'V-228865'
  tag rid: 'SV-228865r831607_rule'
  tag stig_id: 'PANW-AG-000112'
  tag gtitle: 'SRG-NET-000384-ALG-000136'
  tag fix_id: 'F-31077r513891_fix'
  tag 'documentable'
  tag legacy: ['SV-77101', 'V-62611']
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
