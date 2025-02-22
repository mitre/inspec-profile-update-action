control 'SV-89661' do
  title 'The MQ Appliance network device must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses an MQ Appliance network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 

Session termination terminates all processes associated with an administrator's logical session, except processes specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and MQ Appliance network device types."
  desc 'check', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
web-mgmt 
show 

If the idle-timeout value is not 600 seconds or less, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance CLI as a privileged user. 

Enter: 
co 
web-mgmt 
idle-timeout <600 seconds or less> 
exit 
write mem 
y'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74987'
  tag rid: 'SV-89661r1_rule'
  tag stig_id: 'MQMH-ND-000880'
  tag gtitle: 'SRG-APP-000295-NDM-000279'
  tag fix_id: 'F-81603r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
