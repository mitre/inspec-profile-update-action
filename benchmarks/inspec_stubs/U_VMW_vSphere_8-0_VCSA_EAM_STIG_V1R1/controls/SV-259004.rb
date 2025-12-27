control 'SV-259004' do
  title 'The vCenter ESX Agent Manager service cookies must have secure flag set.'
  desc 'The secure flag is an option that can be set by the application server when sending a new cookie to the user within an HTTP Response. The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due to the transmission of a cookie in clear text.

By setting the secure flag, the browser will prevent the transmission of a cookie over an unencrypted channel.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --format /usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/session-config/cookie-config/secure' -

Expected result:

<secure>true</secure>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/webapps/eam/WEB-INF/web.xml

Navigate to the <session-config> node and configure the <secure> setting as follows:

<session-config>
  <session-timeout>30</session-timeout>
  <cookie-config>
      <http-only>true</http-only>
      <secure>true</secure>
  </cookie-config>
</session-config>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA EAM'
  tag check_id: 'C-62744r934668_chk'
  tag severity: 'medium'
  tag gid: 'V-259004'
  tag rid: 'SV-259004r934670_rule'
  tag stig_id: 'VCEM-80-000005'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-62653r934669_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
