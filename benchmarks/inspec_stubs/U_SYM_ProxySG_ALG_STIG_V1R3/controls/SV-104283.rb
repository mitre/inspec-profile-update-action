control 'SV-104283' do
  title 'Symantec ProxySG must identify and log internal users associated with denied outgoing communications traffic posing a threat to external information systems.'
  desc 'Without identifying the users who initiated the traffic, it would be difficult to identify those responsible for the denied communications.

This requirement applies to network elements that perform Data Leakage Prevention (DLP) (e.g., ALGs, proxies, or application level firewalls).'
  desc 'check', 'Verify that the ProxySG is configured to log user web traffic for auditing.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Verify that "Enable Access Logging" is checked.
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, verify that each rule that has "Action" set to "Deny" and "Destination" defined as a restricted set of potentially threatening destinations has a value other than "none" in the "Track".

If Symantec ProxySG does not identify and log internal users associated with denied outgoing communications traffic posing a threat to external information systems, this is a finding.'
  desc 'fix', 'Configure the ProxySG to log user web traffic for auditing.

1. Log on to the Web Management Console.
2. Browse to "Configuration" and click "Access Logging". Check the "Enable Access Logging" option and click "Apply".
3. Click Policy >> Visual Policy Manager >> Launch.
4. For each Web Access Layer, right-click the "Track" column for each rule that has "Action" set to "Deny" and "Destination" defined as a restricted set of potentially threatening destinations and select "Set". 
5. Click "New" and select "Event Log".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93515r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94329'
  tag rid: 'SV-104283r1_rule'
  tag stig_id: 'SYMP-AG-000580'
  tag gtitle: 'SRG-NET-000370-ALG-000125'
  tag fix_id: 'F-100445r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002400']
  tag nist: ['SC-7 (9) (b)']
end
