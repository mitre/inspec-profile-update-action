control 'SV-257556' do
  title 'OpenShift must display an explicit logout message indicating the reliable termination of authenticated communication sessions.'
  desc "The OpenShift CLI tool includes an explicit logout option. 

The web console's default logout will invalidate the user's session token and redirect back to the console page, which will redirect the user to the authentication page. There is no explicit logout message. And in addition, if the IdP provider type is OIDC, the session token from the SSO provider will remain valid, which would effectively keep the user logged in. To correct this, the web console needs to be configured to redirect the user to a logout page. If using an OIDC provider, this would be the logout page for that provider."
  desc 'check', %q(Verify the logout redirect setting in web console configuration is set by executing the following:

oc get console.config.openshift.io cluster -o jsonpath='{.spec.authentication.logoutRedirect}{"\n"}'

If nothing is returned, this is a finding.)
  desc 'fix', %q(Configure the web console's logout redirect to direct to an appropriate logout page. If OpenShift is configured to use an OIDC provider, then the redirect needs to first go to the OIDC provider's logout page, and then it can be redirected to another logout page as needed.

Run the following command to update the console:

oc patch console.config.openshift.io cluster --type merge -p '{"spec":{"authentication":{"logoutRedirect":"<LOGOUT_URL>"}}}'

where LOGOUT_URL is set to the logout page.)
  impact 0.3
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61291r921609_chk'
  tag severity: 'low'
  tag gid: 'V-257556'
  tag rid: 'SV-257556r921611_rule'
  tag stig_id: 'CNTR-OS-000650'
  tag gtitle: 'SRG-APP-000297-CTR-000705'
  tag fix_id: 'F-61215r921610_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
