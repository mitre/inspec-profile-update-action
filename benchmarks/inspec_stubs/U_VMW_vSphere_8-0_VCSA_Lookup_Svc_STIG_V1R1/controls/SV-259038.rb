control 'SV-259038' do
  title 'The vCenter Lookup service cookies must have secure flag set.'
  desc 'The secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response. The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a cookie in clear text.

By setting the secure flag, the browser will prevent the transmission of a cookie over an unencrypted channel.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-lookupsvc/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' -

Expected result:

<secure>true</secure>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/web.xml

Navigate to the <session-config> node and configure the <secure> setting as follows:

<session-config>
  <session-timeout>30</session-timeout>
  <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
  </cookie-config>
</session-config>

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Lookup Service'
  tag check_id: 'C-62778r934770_chk'
  tag severity: 'medium'
  tag gid: 'V-259038'
  tag rid: 'SV-259038r934772_rule'
  tag stig_id: 'VCLU-80-000005'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-62687r934771_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
