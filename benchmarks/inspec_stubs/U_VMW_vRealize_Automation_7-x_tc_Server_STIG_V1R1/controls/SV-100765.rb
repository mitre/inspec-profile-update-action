control 'SV-100765' do
  title 'tc Server ALL must be configured to the correct user authentication source.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. 

vRealize Automation can be configured with a variety of authentication sources. Site policies and procedures will dictate the appropriate authentication mechanism.'
  desc 'check', 'Obtain the correct configuration data for the Authentication Source from the ISSO.  

Open a web browser, and type in the vRA URL.

1. Log on to the Tenant Administration Portal.
2. Click on Administration >> Directories Management.
3. Click on "Policies".
4. Click on the "Policy Set" link.
5. Verify that User Authentication is configured correctly.

If the Authentication Source is not configured in accordance with site policy, this is a finding.'
  desc 'fix', 'Obtain the correct configuration data for the Authentication Source from the ISSO.

Open a web browser, and type in the vRA URL.

1. Log on to the Tenant Administration Portal.
2. Click on Administration >> Directories Management.
3. Click on "Policies".
4. Click on the "Policy Set" link.
5. Modify the Authentication Source in accordance with site policy.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89807r1_chk'
  tag severity: 'high'
  tag gid: 'V-90115'
  tag rid: 'SV-100765r1_rule'
  tag stig_id: 'VRAU-TC-000710'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag fix_id: 'F-96857r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
