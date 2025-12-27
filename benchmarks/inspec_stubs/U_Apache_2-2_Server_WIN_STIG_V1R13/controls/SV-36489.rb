control 'SV-36489' do
  title 'The service account used to run the web service must have its password changed at least annually.'
  desc 'Normally, a service account is established for the web service to run under rather than permitting it to run as part of the local system. The password on such accounts must be changed at least annually. If the password is not changed periodically, the potential for a malicious party to gain access to the web services account is greatly enhanced.'
  desc 'check', 'Interview the ISSO and confirm with the SA, the Web Manager, or the individual in an equivalent role. Ask for the web server’s documented procedures and processes.

Verify the documented procedures and processes identify web server related service accounts, which services are related to web server operations and include a policy requiring service account passwords to be change at least annually.
If the documented procedures and processes do not identify web server related service accounts, which services are related to web server operations and include a policy requiring service account passwords to be change at least annually, this is a finding.'
  desc 'fix', 'Ensure that the service account IDs used to run the web server and sites are documented and have their passwords changed at least annually.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33732r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2235'
  tag rid: 'SV-36489r4_rule'
  tag stig_id: 'WG060 W22'
  tag gtitle: 'WG060'
  tag fix_id: 'F-29367r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
