control 'SV-207706' do
  title 'The Palo Alto Networks security platform must detect use of network services that have not been authorized or approved by the ISSM and ISSO, at a minimum.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.

To comply with this requirement, the IDPS may be configured to detect services either directly or indirectly (i.e., by detecting traffic associated with a service).'
  desc 'check', 'Obtain the list of network services that have not been authorized or approved by the ISSM and ISSO.  For each prohibited network service, view the security policies that denies traffic associated with it and logs the denied traffic.

If there is no list of unauthorized network services, this is a finding.
 
If there are no configured security policies that specifically match the list of unauthorized network services, this is a finding.
 
If the security policies do not deny the traffic associated with the unauthorized network services, this is a finding.'
  desc 'fix', 'Obtain the list of network services that have not been authorized or approved by the ISSM and ISSO.  For each prohibited network service, configure a security policy that denies traffic associated with it and logs the denied traffic.

To create or edit a Security Policy:
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7960r358451_chk'
  tag severity: 'medium'
  tag gid: 'V-207706'
  tag rid: 'SV-207706r856620_rule'
  tag stig_id: 'PANW-IP-000046'
  tag gtitle: 'SRG-NET-000384-IDPS-00209'
  tag fix_id: 'F-7960r358452_fix'
  tag 'documentable'
  tag legacy: ['SV-77173', 'V-62683']
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end
