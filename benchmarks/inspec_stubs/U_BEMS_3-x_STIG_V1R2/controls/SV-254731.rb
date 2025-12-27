control 'SV-254731' do
  title 'If the BlackBerry Presence service is installed on the BlackBerry Enterprise Mobility Server (BEMS), it must be configured with the whitelisting control to limit presence subscriptions to only single domain/tenant.'
  desc 'Whitelisting in Presence subscriptions is used to control which internal and federated environments can be subscribed to. Presence subscriptions should be limited to only DOD environments to control who has access to presence information on DOD users. This is an operational security (OPSEC) issue.'
  desc 'check', 'This requirement is not applicable if the Presence service is not enabled on BEMS.

Verify that Domain whitelisting has been configured.

1. Under the BlackBerry Service Configuration select "Presence".
2. Select "Settings".
3. Confirm "Enable domain whitelisting" has been checked.

If "Enable domain whitelisting" is not selected, this is a finding.'
  desc 'fix', 'Configure Domain Whitelisting for the Presence service.

1. Under the BlackBerry Service Configuration select "Presence".
2. Select "Settings".
3. Confirm "Enable domain whitelisting" has been checked.
4. Click the plus sign and add the domain to whitelist.'
  impact 0.3
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58342r861916_chk'
  tag severity: 'low'
  tag gid: 'V-254731'
  tag rid: 'SV-254731r879887_rule'
  tag stig_id: 'BEMS-03-015000'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-58288r861917_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
