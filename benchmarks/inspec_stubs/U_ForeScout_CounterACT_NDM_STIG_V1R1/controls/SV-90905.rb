control 'SV-90905' do
  title 'CounterACT must enable Threat Protection notifications to alert security personnel to Cyber events detected by a CounterACT IAW CJCSM 6510.01B.'
  desc 'CJCSM 6510.01B, "Cyber Incident Handling Program", in subsection e.(6)(c) sets forth requirements for Cyber events detected by an automated system.

By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged into the network device.'
  desc 'check', 'Verify Threat Protection notifications are enabled and configured.

1. Select Tools >> Options >> Threat Protection.
2. At the bottom of the Threat Protection pane, select "Customer" and then select the "Notify" tab.
3. Verify the Maximum emails per day is set to "15" and infected host notification is set to 1 hour.

If CounterACT does not enable Threat Protection notifications to alert security personnel to Cyber events detected by a CounterACT IAW CJCSM 6510.01B, this is a finding.'
  desc 'fix', 'Enable and configure Threat Protection notifications.

1. Select Tools >> Options >> Threat Protection.
2. At the bottom of the Threat Protection pane, select "Customer" and then select the "Notify" tab.
3. Modify the Maximum emails per day to "15" and infected host notification to 1 hour.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76217'
  tag rid: 'SV-90905r1_rule'
  tag stig_id: 'CACT-NM-000009'
  tag gtitle: 'SRG-APP-000516-NDM-000333'
  tag fix_id: 'F-82853r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end
