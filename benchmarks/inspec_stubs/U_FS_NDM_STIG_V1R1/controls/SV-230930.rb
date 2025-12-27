control 'SV-230930' do
  title 'Forescout must limit the number of concurrent sessions to one for each administrator account.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial of service (DoS) attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Determine if Forescout requires a limit of one session per user. This requirement may be verified by demonstration or configuration review.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterAct user profiles >> Password and Sessions >> Session.
3. Verify the "allow only one login session per user",  "Terminate existing session upon new login", and "Console and web portal sessions cannot exist concurrently".

If Forescout does not enforce one session per user, this is a finding.'
  desc 'fix', 'Configure Forescout to require a limit of one session per user.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterAct user profiles >> Password and Sessions >> Session.
3. Check "allow only one login session per user". 
4. Select the "Terminate existing session upon new login" radio button.
5. Select "Console and web portal sessions cannot exist concurrently".'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33860r603629_chk'
  tag severity: 'low'
  tag gid: 'V-230930'
  tag rid: 'SV-230930r615886_rule'
  tag stig_id: 'FORE-NM-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-33833r603630_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
