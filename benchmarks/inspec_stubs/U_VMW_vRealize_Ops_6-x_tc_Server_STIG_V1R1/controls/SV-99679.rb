control 'SV-99679' do
  title 'tc Server ALL must be configured to the correct user authentication source.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements.

vRealize Operations can be configured with a variety of authentication sources.  Site policies and procedures will dictate the appropriate authentication mechanism.'
  desc 'check', 'Obtain the correct configuration data for the Authentication Source from the ISSO.

Open a web browser, and put in the vROps URL.

1. Log into the Administration Portal
2. Click on Administration >> Authentication Sources
3. Click on Authentication Source
4. Verify that User Authentication is configured correctly

If the Authentication Source is not configured in accordance with site policy, this is a finding.'
  desc 'fix', 'Document the correct configuration data for the Authentication Source and provide to the ISSO.

Open a web browser, and put in the vROps URL.

1. Log into the Administration Portal
2. Click on Administration >> Authentication Sources
3. Click on Authentication Source
4. Ensure that that User Authentication is configured correctly'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88721r1_chk'
  tag severity: 'high'
  tag gid: 'V-89029'
  tag rid: 'SV-99679r1_rule'
  tag stig_id: 'VROM-TC-000735'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag fix_id: 'F-95771r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
