control 'SV-246957' do
  title 'ONTAP must prohibit the use of cached authenticators.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'Use "security login show -authentication-method domain" to see users configured to authenticate with Active Directory.

If ONTAP cannot prohibit the use of cached authenticators, this is a finding.'
  desc 'fix', 'Configure ONTAP to make use of Active Directory to authenticate users to prohibit the use of cached authenticators with "security login create -user-or-group-name <user or group name> -authentication-method domain -application ssh".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50389r769201_chk'
  tag severity: 'medium'
  tag gid: 'V-246957'
  tag rid: 'SV-246957r769203_rule'
  tag stig_id: 'NAOT-IA-000011'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-50343r769202_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
