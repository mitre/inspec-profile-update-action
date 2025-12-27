control 'SV-104291' do
  title 'Symantec ProxySG providing content filtering must generate a log record when access attempts to unauthorized websites and/or services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice over Internet Protocol, Instant Messaging, auto-execute, and file sharing.'
  desc 'check', 'Verify that the ProxySG is configured to log access attempts to unauthorized websites and/or services.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, verify that each rule has a value other than "none" in the "Track" column.

If Symantec ProxySG providing content filtering does not generate a log record when access attempts to unauthorized websites and/or services are detected, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log access attempts to unauthorized websites and/or services.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check the "Enable Access Logging" option and click "Apply".
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, right-click the "Track" column for each rule and select "Set". 
5. Click "New" and select "Event Log".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94337'
  tag rid: 'SV-104291r1_rule'
  tag stig_id: 'SYMP-AG-000620'
  tag gtitle: 'SRG-NET-000385-ALG-000137'
  tag fix_id: 'F-100453r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end
