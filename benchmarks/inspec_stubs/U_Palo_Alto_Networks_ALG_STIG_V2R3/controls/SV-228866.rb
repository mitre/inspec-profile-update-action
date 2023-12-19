control 'SV-228866' do
  title 'The Palo Alto Networks security platform must generate a log record when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.'
  desc 'check', 'Obtain the list of network services that have not been authorized or approved by the ISSM and ISSO.
For each prohibited network service, view the security policies that denies traffic associated with it and logs the denied traffic.
 
To verify if a Security Policy logs denied traffic:
Go to Policies >> Security
Select the name of the security policy to view it.
In the "Actions" tab, in the "Log Setting" section, if neither the "Log at Session Start" nor the "Log at Session End" check boxes are checked, this is a finding.'
  desc 'fix', 'To configure a Security Policy to log denied traffic:
Go to Policies >> Security
Select "Add" to create a new security policy, or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
In the "Actions" tab, select the Log forwarding profile and select "Log at Session End".
"Log at Session Start" may be selected under specific circumstances, but "Log at Session End" is preferred.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31101r513893_chk'
  tag severity: 'medium'
  tag gid: 'V-228866'
  tag rid: 'SV-228866r831608_rule'
  tag stig_id: 'PANW-AG-000113'
  tag gtitle: 'SRG-NET-000385-ALG-000137'
  tag fix_id: 'F-31078r513894_fix'
  tag 'documentable'
  tag legacy: ['V-62613', 'SV-77103']
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
