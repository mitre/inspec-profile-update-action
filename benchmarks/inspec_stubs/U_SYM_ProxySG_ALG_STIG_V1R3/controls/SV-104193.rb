control 'SV-104193' do
  title 'Symantec ProxySG providing user access control intermediary services must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that the ProxySG is configured to generate alerts for successful/unsuccessful logon attempts.

1. Log on to the Web Management console.
2. Browse to "Configuration" and Click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, verify that each rule has a value other than "none" in the "Track" column.

If Symantec ProxySG providing user access control intermediary services does not generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the ProxySG to generate alerts for successful/unsuccessful logon attempts.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check the "Enable Access Logging" option and click "Apply".
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access and Web Authentication Layer, right-click the "Track" column for each rule and select "Set". Click "New" and select "Event Log".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93425r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94239'
  tag rid: 'SV-104193r1_rule'
  tag stig_id: 'SYMP-AG-000120'
  tag gtitle: 'SRG-NET-000503-ALG-000038'
  tag fix_id: 'F-100355r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
