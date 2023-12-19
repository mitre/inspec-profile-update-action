control 'SV-214306' do
  title 'The Apache web server must limit the number of allowed simultaneous session requests.'
  desc 'Apache web server management includes the ability to control the number of users and user sessions that utilize an Apache web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of denial-of-service (DoS) attacks.

Although there is some latitude concerning the settings, they should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'With an editor, open the configuration file:

<installed path>\\Apache24\\conf\\extra\\httpd-default

Search for the following directive:

MaxKeepAliveRequests

Verify the value is "100" or greater.

If the "MaxKeepAliveRequests" directive is not "100" or greater, this is a finding.'
  desc 'fix', 'With an editor, open the configuration file:

<installed path>\\conf\\extra\\httpd-default

Search for the following directive:

MaxKeepAliveRequests

Set the "MaxKeepAliveRequests" directive to a value of "100" or greater. Add the "MaxKeepAliveRequests" directive if it does not exist.

It is recommended that the "MaxKeepAliveRequests" directive be explicitly set to prevent unexpected results if the defaults change with updated software.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15518r277421_chk'
  tag severity: 'medium'
  tag gid: 'V-214306'
  tag rid: 'SV-214306r505936_rule'
  tag stig_id: 'AS24-W1-000010'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-15516r277422_fix'
  tag 'documentable'
  tag legacy: ['SV-102415', 'V-92327']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
