control 'SV-251598' do
  title 'IDMS must protect against the use web services that do not require a sign on when actions are performed that may be audited.'
  desc 'IDMS web services provide a way for web-based applications to access an IDMS database. If not secured, the Web services interface could be used to reveal or change sensitive data.'
  desc 'check', 'On the IDMS CV system where CA IDMS Web Services executes, enter "WEBC" to check Web Services configuration.

If "REQUIRE SIGNON = NO", this is a finding.'
  desc 'fix', 'On the IDMS CV system where CA IDMS Web Services executes, enter "WEBC REQUIRE SIGNON=YES".'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55033r807659_chk'
  tag severity: 'low'
  tag gid: 'V-251598'
  tag rid: 'SV-251598r807661_rule'
  tag stig_id: 'IDMS-DB-000180'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-54987r807660_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
