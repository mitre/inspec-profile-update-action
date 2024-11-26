control 'SV-96039' do
  title 'The WebSphere Application Server must provide security extensions to extend the SOAP protocol and provide secure authentication when accessing sensitive data.'
  desc 'Application servers may provide a web services capability that could be leveraged to allow remote access to sensitive application data. A web service which is a repeatable process used to make data available to remote clients, should not be confused with a web server. 

Many web services utilize SOAP, which in turn utilizes XML and HTTP as a transport. Natively, SOAP does not provide security protections. As such, the application server must provide security extensions to enhance SOAP capabilities to ensure that secure authentication mechanisms are employed to protect sensitive data. The WS_Security suite is a widely used and acceptable SOAP security extension.'
  desc 'check', 'Review System Security Plan documentation.

Interview the system administrator.

Identify any application web service providers and the secure authentication requirements for each service provider. 

From admin console, navigate to Applications >> All applications.

Click on each application that is a web service provider where the security plan specifies security extensions are to be applied. 

Navigate to "Service provider policy sets and bindings".

Verify that any web service providers that are required to have security extensions applied as per the security plan have a policy attached.

If "Attached policy set" column displays none, but the System Security Plan specifies security extensions as required, this is a finding.'
  desc 'fix', 'To attach policy sets for your service providers: 
From admin console, navigate to Applications >> All applications >> [application]. 

For each application that is a web service provider and requires secure authentication, click on "Service provider policy sets and bindings."

Click button on the "Select" column to select a resource. 

Click on "Attach Policy Set" drop down.

Select policy set that best matches the provider environment.

Click button on the "Select" column to select the same resource.

Click on the "Assign binding" drop down.

Select a binding that best matches the environment.

Click "Save".

Restart DMGR and resync the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81027r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81325'
  tag rid: 'SV-96039r1_rule'
  tag stig_id: 'WBSP-AS-001080'
  tag gtitle: 'SRG-APP-000156-AS-000106'
  tag fix_id: 'F-88109r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
