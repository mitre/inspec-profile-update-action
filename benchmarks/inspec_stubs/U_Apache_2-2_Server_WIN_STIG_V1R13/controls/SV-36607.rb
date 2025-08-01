control 'SV-36607' do
  title 'The web server, although started by superuser or privileged account, must run using a non-privileged account.'
  desc 'Running the web server with excessive privileges presents an increased risk to the web server. In the event the web server’s services are compromised, the context by which the web server is running will determine the amount of damage that may be caused by the attacker. If the web server is run as an administrator or as an equivalent account, the attacker will gain administrative access through the web server. If, on the other hand, the web server is running with least privilege required to function, the capabilities of the attacker will be greatly decreased.'
  desc 'check', 'Work with the web administrator to determine the account assigned to the web server service. Once this is determined, right click on My Computer and select Manage. Then select Configuration, followed by Local Users and Groups. 

Examine the account that is used to run the web server service and determine the group affiliations. The Apache server account may be a member of the users group and in some cases the site may have created a separate group for the apache web server. Both of these are not findings. 

If the user account assigned to the web server service is a member of any other group than users or the created web server group, the SA will need to provide justification showing that these permissions are necessary for the function and operation of the web server.

NOTE: The Apache account needs to have the following rights, which would not be a finding: Act as part of the Operating System & Log on as a Service.'
  desc 'fix', 'Configure the web server to run using a non-privileged account.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33748r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13619'
  tag rid: 'SV-36607r1_rule'
  tag stig_id: 'WG275 W22'
  tag gtitle: 'WG275'
  tag fix_id: 'F-29384r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
